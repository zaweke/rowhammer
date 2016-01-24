#define DEBUG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/cpumask.h> 
#include <linux/slab.h> 
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <linux/delay.h>

#include "anvil.h"

#define MIN_SAMPLES 0
#define REFRESHED_ROWS 1

#define get_bank(page) ((page>>2)&7)^((page>>6)&7)

MODULE_LICENSE("GPL");

static struct hrtimer sample_timer;
static ktime_t ktime;
static u64 old_val,val;
static u64 old_l1D_val,l1D_val,miss_total;
static sample_t sample_buffer[SAMPLES_MAX];
static int sampling;
static int start_sampling=0;
static int sample_head;
static unsigned int sample_total;
static profile_t profile[PROFILE_N];
static unsigned int record_size;
/* counts number of times L1 threhold was passed (sampling was done) */
static unsigned long L1_count=0;
/* counts number of times hammering was detected */
static unsigned long L2_count=0;
static unsigned long refresh_count=0;
static unsigned int hammer_threshold;
unsigned long dummy;

/* for logging */
static struct sample_log log[25000];
static int log_index=0;

static struct workqueue_struct *action_wq;
static struct workqueue_struct *llc_event_wq;
static struct work_struct task;
static struct work_struct task2;

static void sort(void);
static void build_profile(void);
DEFINE_PER_CPU(struct perf_event *, llc_event);
DEFINE_PER_CPU(struct perf_event *, l1D_event);
DEFINE_PER_CPU(struct perf_event *, ld_lat_event);
DEFINE_PER_CPU(struct perf_event *, precise_str_event);

void action_wq_callback( struct work_struct *work);
void llc_event_wq_callback( struct work_struct *work);

void llc_event_callback(struct perf_event *event,
            struct perf_sample_data *data,
            struct pt_regs *regs){}

void l1D_event_callback(struct perf_event *event,
            struct perf_sample_data *data,
            struct pt_regs *regs){}

/* returns a pfn of a page "inc" rows above the page "phy" in a base row */ 
/*@input: phy - physical page in base DRAM row
@input: inc - offset to the base row

@return: pfn of page in the row base row - inc
*/

static unsigned long get_row_plus(unsigned long phy, int inc){
	unsigned long bank_old = get_bank(phy);
	unsigned long row_new = (phy>>6) + inc;
	unsigned long bank_new = (row_new & 0x7) ^ bank_old;
	unsigned long rank_new = (phy>>7)&1;

	return (unsigned long)((row_new << 6) | (rank_new << 5) | (bank_new << 2) | (phy & 0x3));

}

/* returns a pfn of a page "dec" rows below the page "phy" in a base row */ 
/*@input: phy - physical page in base DRAM row
@input: dec - offset to the base row

@return: pfn of page in the row base row - dec
*/

static unsigned long get_row_minus(unsigned long phy, int dec){
	unsigned long bank_old = get_bank(phy);
	unsigned long row_new = (phy>>6) - dec;
	unsigned long bank_new = (row_new & 0x7) ^ bank_old;
	unsigned long rank_new = (phy>>7)&1;

return  (unsigned long)((row_new << 6) | (rank_new << 5) | (bank_new << 2) | (phy & 0x3));

}


/* convert virtual address from user process into physical address */
/* @input: mm - memory discriptor user process
			@input: virt - virtual address

			@return: corresponding physical address of "virt"*/

static unsigned long virt_to_phy( struct mm_struct *mm,unsigned long virt)
{
	unsigned long phys;
	struct page *pg;
	int ret = get_user_pages (	NULL,
 																								mm,
 																								virt,
 																									1,
 																									0,
 																									0,
 																									&pg,
 																									NULL);

		if(ret <= 0)
				return 0;
		//get physical address
		phys = page_to_phys(pg);

		return phys;
	
}

/* Interrupt handler for store sample */
void precise_str_callback(struct perf_event *event,
            struct perf_sample_data *data,
            struct pt_regs *regs){
	
	/* Check source of store, if local dram (|0x80) record sample */
	if(data->data_src.val & (1<<7)){
	
		sample_buffer[sample_head].phy_page = virt_to_phy(current->mm,data->addr)>>12;
		if(sample_buffer[sample_head].phy_page > 0){
				sample_buffer[sample_head].addr = data->addr;
				/* limit sample index */
				if(++sample_head > SAMPLES_MAX-1)
								sample_head = SAMPLES_MAX-1;

				sample_total++;
			}
		}
}

/* Interrupt handler for load sample */
void load_latency_callback(struct perf_event *event,
            struct perf_sample_data *data,
            struct pt_regs *regs){
	
	sample_buffer[sample_head].phy_page = virt_to_phy(current->mm,data->addr)>>12;
//	if(sample_buffer[sample_head].phy_page > 0){

		#ifdef DEBUG
		sample_buffer[sample_head].addr = data->addr;
		sample_buffer[sample_head].lat = data->weight;
		#endif

	/* limit sample index */
	if(++sample_head > SAMPLES_MAX-1)
				sample_head = SAMPLES_MAX-1;

		sample_total++;
//	}
	
}

void llc_event_wq_callback(struct work_struct *work){
			int cpu;
			u64 enabled,running;
			u64 ld_miss;

			/* If we were sampling, stop sampling and analyze samples */
			if(sampling){

					/* stop sampling */
					for_each_online_cpu(cpu){
							perf_event_disable(per_cpu(ld_lat_event,cpu));
							perf_event_disable(per_cpu(precise_str_event,cpu));
					}
			
					sampling = 0;

					
					/* start task that anayzes samples and take action */ 
					 queue_work(action_wq, &task);
			}
								
			else if(start_sampling){

						/* update MEM_LOAD_UOPS_MISC_RETIRED_LLC_MISS value */
							l1D_val = 0;
							for_each_online_cpu(cpu){
        		l1D_val += perf_event_read_value(per_cpu(l1D_event,cpu), &enabled, &running);
							}
							
							ld_miss = l1D_val - old_l1D_val;
						
						/* Sample loads, stores or both based on LLC load miss count */
							if(ld_miss >= (miss_total*9)/10){
									for_each_online_cpu(cpu){
											perf_event_enable(per_cpu(ld_lat_event,cpu));//sample loads only
									}
							}

							else if(ld_miss < miss_total/10){
											for_each_online_cpu(cpu){
											perf_event_enable(per_cpu(precise_str_event,cpu));//sample stores only
									}
							}

							else{
											for_each_online_cpu(cpu){
											/* sample both */
											perf_event_enable(per_cpu(ld_lat_event,cpu));
											perf_event_enable(per_cpu(precise_str_event,cpu));
											}			
							}
							
						sample_total = 0;
						record_size 	= 0;
						sample_head 	= 0;
			
						//log how many times we passed the threshold
						L1_count++;
						start_sampling = 0;
						sampling = 1;
			}

			old_l1D_val = l1D_val;
}

/* look at sample profile and take action */
 void action_wq_callback( struct work_struct *work)
{
 int rec,log_;
	unsigned long pfn1,pfn2;
	unsigned long *virt;
	struct page *pg1,*pg2;
	int i;
		
	/* group samples based on physical pages */
	build_profile();
	/* sort profile, address with highest number of samples first */
	sort();

	#ifdef DEBUG
	log_=0;
	#endif

if(miss_total > LLC_MISS_THRESHOLD){//if still  high miss
		printk("samples = %u\n",sample_total);
		/* calculate hammer threshold */
		hammer_threshold = (LLC_MISS_THRESHOLD*sample_total)/miss_total;

		/* check for potential agressors */
		for(rec = 0;rec<record_size;rec++){

				#ifdef DEBUG
				profile[rec].hammer = 0;
				#endif
				if((profile[rec].llc_total_miss >= hammer_threshold/2) && (sample_total>= MIN_SAMPLES)){
						#ifdef DEBUG
						log_ = 1;
						profile[rec].hammer = 1;
						L2_count++;
						#endif


				/* potential hammering detected , deploy refresh */
				for(i=1;i<=REFRESHED_ROWS;i++){
					/* get page frame number for pages in rows above and below */
						pfn1 = get_row_plus(profile[rec].phy_page,i);//pfn for victim row1
						pfn2= 	get_row_minus(profile[rec].phy_page,i);//pfn for victim row2

						/* get physical page */
						pg1 = pfn_to_page(pfn1);
						pg2 = pfn_to_page(pfn2);
			
						/* map pages to kernel space and refresh */
						virt = (unsigned long*)kmap(pg1);
						if(virt){
								asm volatile("clflush (%0)"::"r"(virt):"memory");
								get_user(profile[rec].dummy1,virt);
								kunmap(pg1);
						}

						virt = (unsigned long*)kmap(pg2);
						if(virt){
								asm volatile("clflush (%0)"::"r"(virt):"memory");
								get_user(profile[rec].dummy2,virt);
								kunmap(pg2);
						}
				}
				#ifdef DEBUG
				refresh_count++;
				#endif
//}
			}
		}
}

		#ifdef DEBUG
		if(log_){
										//Log
			for(rec = 0;rec<record_size;rec++){
				log[log_index].profile[rec].phy_page = profile[rec].phy_page;
				log[log_index].profile[rec].llc_percent_miss = profile[rec].llc_percent_miss;
				log[log_index].profile[rec].dummy1 = profile[rec].dummy1;
				log[log_index].profile[rec].dummy2 = profile[rec].dummy2;
				log[log_index].profile[rec].hammer = profile[rec].hammer;
			}
			log[log_index].record_size = record_size;
			log[log_index].sample_total = sample_total;
			log_index++;
			if(log_index>24999)
					log_index = 24999;
		}
		#endif
  return;
}

/* Timer interrupt handler */
enum hrtimer_restart timer_callback( struct hrtimer *timer )
		{
    ktime_t now;
				u64 enabled,running;
				int cpu;
        
    /* Update llc miss counter value */
					val = 0;
					for_each_online_cpu(cpu){
       val += perf_event_read_value(per_cpu(llc_event,cpu), &enabled, &running);
					}

					miss_total = val - old_val;
					old_val = val;

					if(!sampling){
							/* Start sampling if miss rate is high */
						if(miss_total > LLC_MISS_THRESHOLD){
								start_sampling = 1;

								/* set next interrupt interval for sampling */
								ktime = ktime_set(0,sample_timer_period);
      		now = hrtimer_cb_get_time(timer); 
      		hrtimer_forward(&sample_timer,now,ktime);
						}

						else{
											/* set next interrupt interval for counting */
									ktime = ktime_set(0,count_timer_period);
     				now = hrtimer_cb_get_time(timer); 
      			hrtimer_forward(&sample_timer,now,ktime);
						}
					}

					else{
							ktime = ktime_set(0,count_timer_period);
     		now = hrtimer_cb_get_time(timer); 
      	hrtimer_forward(&sample_timer,now,ktime);
					}
				
					/* start task that analyzes llc misses */
					queue_work(llc_event_wq, &task2);

					/* restart timer */
   	 return HRTIMER_RESTART;
}

/* Groups samples accoriding to accessed physical pages */
static void build_profile(void){

	int rec,smpl,recorded;
	sample_t sample;

	if(sample_total > 0){
		 sample = sample_buffer[0];
			profile[0].phy_page 	= sample.phy_page;
			profile[0].page = (sample.addr);
			profile[0].llc_total_miss = 1;
			profile[0].llc_percent_miss = 100;
			profile[0].cpu 	= sample.cpu;
			record_size = 1;
			
			for(smpl=1;smpl<sample_head;smpl++){
					sample = sample_buffer[smpl];

					//see if page already exists
					recorded = 0;
					for(rec=0;rec<record_size;rec++){
						if((profile[rec].phy_page != 0) && (profile[rec].phy_page == sample.phy_page)){
								profile[rec].llc_total_miss++;
								profile[rec].cpu 	= sample.cpu;
								recorded = 1;
								break;
						}
				}

				if(!recorded){
						//Must be new record
						//If there is space in the profile add new record
						//else replace the last one  (The least miss in the profile)
						if(record_size < PROFILE_N){
								profile[record_size].phy_page 	= sample.phy_page;
								profile[record_size].page = (sample.addr);
								profile[record_size].llc_total_miss = 1;
								profile[record_size].cpu = sample.cpu;
							record_size++;
						}

						else{//replace
								profile[record_size - 1].phy_page = sample.phy_page;
								profile[record_size - 1].page = (sample.addr);
								profile[record_size - 1].llc_total_miss = 1;
								profile[record_size - 1].cpu = sample.cpu;
						}
				}
		}

	#ifdef DEBUG
	//calculate percentage
		for(rec=0;rec<record_size;rec++){
				profile[rec].llc_percent_miss = (profile[rec].llc_total_miss*100)/sample_total;
		}
	#endif
	}
}

/* Sort addresses with higest address distribution first */
static void sort(void){
	int swapped,rec;
	do{
			swapped = 0;
			for(rec = 1; rec<record_size; rec++){
					if(profile[rec-1].llc_percent_miss < profile[rec].llc_percent_miss){
							//swap
							profile_t temp = profile[rec-1];
							profile[rec-1] = profile[rec];
							profile[rec] = temp;
							swapped = 1;
					}
			}

	}while(swapped);
}


/* Initialize module */
static int start_init(void)
{
			int cpu;

			old_val = 0;

			/* Setup LLC Miss event */
			for_each_online_cpu(cpu){
   			per_cpu(llc_event, cpu) = perf_event_create_kernel_counter(&llc_miss_event, cpu,
                 NULL,llc_event_callback,NULL);
   	 	if(IS_ERR(per_cpu(llc_event, cpu))){
        printk("Error creating llc event.\n");
        return 0;
    		}
						
						/* start counting */
						perf_event_enable(per_cpu(llc_event, cpu));
			}

			old_l1D_val = 0;
			/* Setup LLC Miss event */
			for_each_online_cpu(cpu){
   				per_cpu(l1D_event, cpu) = perf_event_create_kernel_counter(&l1D_miss_event, cpu,
                 NULL,l1D_event_callback,NULL);
   	 	if(IS_ERR(per_cpu(l1D_event, cpu))){
        printk("Error creating l1D miss event.\n");
        return 0;
    		}
						
						/* start counting */
						perf_event_enable(per_cpu(l1D_event, cpu));
			}

		/* setup load latency event */
				for_each_online_cpu(cpu){
   			per_cpu(ld_lat_event, cpu) = perf_event_create_kernel_counter(&load_latency_event, cpu,
                 NULL,load_latency_callback,NULL);
   	 	if(IS_ERR(per_cpu(ld_lat_event, cpu))){
        printk("Error creating load latency event.\n");
        return 0;
    		}
			}

		/* setup precise store event */
				for_each_online_cpu(cpu){
   			per_cpu(precise_str_event, cpu) = perf_event_create_kernel_counter(&precise_str_event_attr, cpu,
                 NULL,precise_str_callback,NULL);
   	 	if(IS_ERR(per_cpu(precise_str_event, cpu))){
        printk("Error creating precise store event.\n");
        return 0;
    		}
			}

    /* Setup Timer */
    ktime = ktime_set(0,count_timer_period);
    hrtimer_init(&sample_timer,CLOCK_REALTIME,HRTIMER_MODE_REL);
    sample_timer.function = &timer_callback;
    hrtimer_start(&sample_timer,ktime,HRTIMER_MODE_REL);
     
				/* Initialize work queue */
		 	action_wq = create_workqueue("action_queue");
				INIT_WORK(&task, action_wq_callback);

				llc_event_wq = create_workqueue("llc_event_queue");
				INIT_WORK(&task2, llc_event_wq_callback);

				printk("done initializing\n");
  	
   return 0;
}

/* Cleanup module */
static void finish_exit(void)
{
    int ret,cpu,i,j; 
    /* timer */
    ret = hrtimer_cancel(&sample_timer);

    /* llc_event */
				for_each_online_cpu(cpu){
    			if(per_cpu(llc_event, cpu)){
        		perf_event_disable(per_cpu(llc_event, cpu));
        		perf_event_release_kernel(per_cpu(llc_event, cpu));
    			}
				}

			 /* l1D_event */
				for_each_online_cpu(cpu){
    			if(per_cpu(l1D_event, cpu)){
        		perf_event_disable(per_cpu(l1D_event, cpu));
        		perf_event_release_kernel(per_cpu(l1D_event, cpu));
    			}
				}

				/* load latency event */
				for_each_online_cpu(cpu){
    			if(per_cpu(ld_lat_event, cpu)){
        		perf_event_disable(per_cpu(ld_lat_event, cpu));
        		perf_event_release_kernel(per_cpu(ld_lat_event, cpu));
    			}
				}

				/* precise store event */
				for_each_online_cpu(cpu){
    			if(per_cpu(precise_str_event, cpu)){
        		perf_event_disable(per_cpu(precise_str_event, cpu));
        		perf_event_release_kernel(per_cpu(precise_str_event, cpu));
    			}
				}


			flush_workqueue(action_wq);
  	destroy_workqueue(action_wq);

			flush_workqueue(llc_event_wq);
  	destroy_workqueue(llc_event_wq);

			#ifdef DEBUG
			// Log of ANVIL. CSV of some of the sampled/detected addresses
			 
			printk(">>>>>>>>>>>>>>>>log dump>>>>>>>>>>>>>>>\n");
			//dump all the logs
			for(i=0;i<log_index;i++)
			{

					for(j=0;j<4;j++){
							/* physical pages */
								printk("%lu,",log[i].profile[j].phy_page);
					}

				for(j=0;j<4;j++){
								/* Values read form row above and row below */
								printk("%d,",log[i].profile[j].hammer);
								printk("0x%lx,",log[i].profile[j].dummy1);
								printk("0x%lx,",log[i].profile[j].dummy2);
					}
					
							/* Total samples per sample period */
							printk("%u\n",log[i].sample_total);

			}
				/* L1 count: Number of times LLC_MISS_THRESHOLD was crossed
							L2 count: Number of times potential hammer activity was detected
							Refresh: Number of addresses that resulted in refreshes */
					printk("L1 count = %lu\n",L1_count);
					printk("L2 count = %lu\n",L2_count);
					printk("Refreshs = %lu\n",refresh_count);
					printk(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    return;
		#endif
}

module_init(start_init);
module_exit(finish_exit);
