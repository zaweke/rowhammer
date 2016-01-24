
#include <linux/perf_event.h>


#define LOAD_LATENCY_EVENT 0x01CD
#define PRECISE_STORE_EVENT 0x02CD
#define MEM_LOAD_UOPS_MISC_RETIRED_LLC_MISS 0x02D4

/* controls load sampling rate */
#define LD_LAT_SAMPLE_PERIOD 50		

/* controls store sampling rate */
#define PRE_STR_SAMPLE_PERIOD 3000

/* count period in nanoseconds */
#define count_timer_period 6000000 	

/* sample period  in nanoseconds */
#define sample_timer_period 6000000 					

/* last-level cache miss rate threshold
			that triggers sampling            */
#define LLC_MISS_THRESHOLD			20000

/* Maximum number of addresses in the address profile */
#define PROFILE_N 20

/* Maximum number of samples */
#define SAMPLES_MAX 150

/* LLC miss event attribute */
static struct perf_event_attr llc_miss_event = {
    .type = PERF_TYPE_HARDWARE,
    .config = PERF_COUNT_HW_CACHE_MISSES,    
    .exclude_user  	= 0,      
    .exclude_kernel = 1,        
				.pinned = 1,
};

/* Load uops that misses LLC */
static struct perf_event_attr l1D_miss_event = {
    .type =  PERF_TYPE_RAW,
    .config = MEM_LOAD_UOPS_MISC_RETIRED_LLC_MISS,    
    .exclude_user  	= 0,       
    .exclude_kernel = 1,        
				.pinned = 1,
};


/* Load latency event attribute */
static struct perf_event_attr load_latency_event = {
    .type = PERF_TYPE_RAW,
    .config = LOAD_LATENCY_EVENT, 
				.config1 = 150, //latency?   
				.sample_type = 
																			PERF_SAMPLE_ADDR 				|			//Sample address
																			PERF_SAMPLE_DATA_SRC | 		//Sample data source 
																			PERF_SAMPLE_WEIGHT,						//Sample latency in clock cycles
				.sample_period = 	LD_LAT_SAMPLE_PERIOD, //How many samples before overflow(interrupt)
    .exclude_user  = 0,        													//count user
    .exclude_kernel = 1,        												//don't count kernel
				.precise_ip 				= 1,																				// Enables precise event
				.wakeup_events 	= 1,																				//overflow on each sample
				.disabled = 1,
				.pinned = 1,
};

/*precise store event*/
static struct perf_event_attr precise_str_event_attr = {
    .type = PERF_TYPE_RAW,
    .config = PRECISE_STORE_EVENT,   
				.sample_type =
																			PERF_SAMPLE_ADDR 				|		
																			PERF_SAMPLE_DATA_SRC , 	
																		
				.sample_period = 	PRE_STR_SAMPLE_PERIOD, 
    .exclude_user   = 0,        						
    .exclude_kernel = 1,        												
				.precise_ip 				= 1,																				
				.wakeup_events 	= 1,
				.disabled 						= 1,
				.pinned 								= 1,
};

/* Address profile */
typedef struct{
	unsigned long phy_page;
	unsigned long page;
	int ld_st;
	unsigned long llc_total_miss;
	unsigned int llc_percent_miss;
	int cpu;
unsigned long dummy1;
unsigned long dummy2;
int hammer;
} profile_t;

/* Address sample */
typedef struct{
	unsigned long phy_page;
	u64 addr;
	u64 lat;
	u64 time;
	unsigned int src;
	int ld_st;//sample is load or store
	int cpu;
}sample_t;

/* for logging */
struct sample_log{
	profile_t profile[20];
	unsigned int record_size;
	unsigned int sample_total;
	unsigned int hammer_threshold;
	int cpu;
};


