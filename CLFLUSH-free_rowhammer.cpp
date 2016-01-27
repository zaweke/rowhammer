/***************************************************************
A program to test CLFLUSH-free rowhammering

The program is based on the double-sided rowhammring 
program at https://github.com/google/rowhammer-test/

**************************************************************/


// Copyright 2015, Google, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Small test program to systematically check through the memory to find bit
// flips by double-sided row hammering.
//
// Compilation instructions:
//   g++ -std=c++11 [filename]
//
// ./double_sided_rowhammer [-t nsecs] [-p percentage]
//
// Hammers for nsecs seconds, acquires the described fraction of memory (0.0
// to 0.9 or so).

#include <asm/unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kernel-page-flags.h>
#include <map>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <pthread.h>

#define DEBUG

#define TOTAL_ACCESS (1024*1000)/14
#define INDEX_SIZE 210


int dummy,dummy2;
// The fraction of physical memory that should be mapped for testing.
double fraction_of_physical_memory = 0.3;

// The time to hammer before aborting. Defaults to one hour.
uint64_t number_of_seconds_to_hammer = 3600;

// The number of memory reads to try.
uint64_t number_of_reads = 1000*1024;

int pagemap;
uintptr_t end_addr;
const int size = 13;
const int addr_count = 22;

volatile  uintptr_t first_addrs[size];
volatile  uintptr_t second_addrs[size];	
uintptr_t phy_addr1[size];
uintptr_t phy_addr2[size];

// Indexes of conflicting addresses in the access patern 
volatile  int indexes1[]={0,1,2,3,4,5,6,7,8,9,10,
													12,1,2,3,4,5,6,7,8,9,11};

volatile int indexes2[]={0,1,2,3,4,5,6,7,8,9,10,
													12,1,2,3,4,5,6,7,8,9,11};

// Obtain the size of the physical memory of the system.
uint64_t GetPhysicalMemorySize() {
  struct sysinfo info;
  sysinfo( &info );
  return (size_t)info.totalram * (size_t)info.mem_unit;
}

// If physical_address is in the range, put (physical_address, virtual_address)
// into the map.
bool PutPointerIfInAddressRange(const std::pair<uint64_t, uint64_t>& range,
    uint64_t physical_address, uint8_t* virtual_address,
    std::map<uint64_t, uint8_t*>& pointers) {
  if (physical_address >= range.first && physical_address <= range.second) {
    printf("[!] Found desired physical address %lx at virtual %lx\n", 
        (uint64_t)physical_address, (uint64_t)virtual_address);
    pointers[physical_address] = virtual_address;
    return true;
  }
  return false;
}

bool IsRangeInMap(const std::pair<uint64_t, uint64_t>& range,
    const std::map<uint64_t, uint8_t*>& mapping) {
  for (uint64_t check = range.first; check <= range.second; check += 0x1000) {
    if (mapping.find(check) == mapping.end()) {
      printf("[!] Failed to find physical memory at %lx\n", check);
      return false;
    }
  }
  return true;
}

uint64_t GetPageFrameNumber(int pagemap, uint8_t* virtual_address) {
  // Read the entry in the pagemap.
  uint64_t value;
  int got = pread(pagemap, &value, 8,
                  (reinterpret_cast<uintptr_t>(virtual_address) / 0x1000) * 8);
  assert(got == 8);
  uint64_t page_frame_number = value & ((1ULL << 54)-1);
  return page_frame_number;
}

void SetupMapping(size_t* mapping_size, void** mapping) {
    *mapping_size = 
    static_cast<uint64_t>((static_cast<double>(GetPhysicalMemorySize()) * 
          fraction_of_physical_memory));

  *mapping = mmap(NULL, *mapping_size, PROT_READ | PROT_WRITE,
      MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  assert(*mapping != (void*)-1);

	end_addr = (uintptr_t)((uintptr_t)*mapping + *mapping_size);
  // Initialize the mapping so that the pages are non-empty.
  printf("[!] Initializing large memory mapping ...");
  for (uint64_t index = 0; index < *mapping_size; index += 0x1000) {
    uint64_t* temporary = reinterpret_cast<uint64_t*>(
        static_cast<uint8_t*>(*mapping) + index);
    temporary[0] = index;
  }
  printf("done\n");
}


int get_cache_slice(uint64_t phys_addr, int bad_bit) {
  // On a 4-core machine, the CPU's hash function produces a 2-bit
  // cache slice number, where the two bits are defined by "h1" and
  // "h2":
  //
  // h1 function:
  //   static const int bits[] = { 18, 19, 21, 23, 25, 27, 29, 30, 31 };
  // h2 function:
  //   static const int bits[] = { 17, 19, 20, 21, 22, 23, 24, 26, 28, 29, 31 };
  //
  // This hash function is described in the paper "Practical Timing
  // Side Channel Attacks Against Kernel Space ASLR".
  //
  // On a 2-core machine, the CPU's hash function produces a 1-bit
  // cache slice number which appears to be the XOR of h1 and h2.

  // XOR of h1 and h2:
  static const int bits[] = { 17, 18, 20, 22, 24, 25, 26, 27, 28, 30 };

  int count = sizeof(bits) / sizeof(bits[0]);
  int hash = 0;
  for (int i = 0; i < count; i++) {
    hash ^= (phys_addr >> bits[i]) & 1;
  }
  if (bad_bit != -1) {
    hash ^= (phys_addr >> bad_bit) & 1;
  }
  return hash;
}

// Extract the physical page number from a Linux /proc/PID/pagemap entry.
uint64_t frame_number_from_pagemap(uint64_t value) {
  return value & ((1ULL << 54) - 1);
}

uint64_t get_physical_addr(uintptr_t virtual_addr) {
  uint64_t value;
		const int page_size = 0x1000;
  off_t offset = (virtual_addr / page_size) * sizeof(value);
  int got = pread(pagemap, &value, sizeof(value), offset);
		if(got!=8)
		return 0;
 		assert(got == 8);

  //Check the "page present" flag.
  	assert(value & (1ULL << 63));
		if(!(value & (1ULL << 63)))
			return 0;

  uint64_t frame_num = frame_number_from_pagemap(value);
  return (frame_num * page_size) | (virtual_addr & (page_size - 1));
}

//checks if two addresses map to the same cache line
bool in_same_cache_set(uint64_t phys1, uint64_t phys2, int bad_bit) {
  // For Sandy Bridge, the bottom 17 bits determine the cache set
  // within the cache slice (or the location within a cache line).
  uint64_t mask = ((uint64_t) 1 << 17) - 1;
  return ((phys1 & mask) == (phys2 & mask) &&
          get_cache_slice(phys1, bad_bit) == get_cache_slice(phys2, bad_bit));
}

inline void mfence() {
  asm volatile("mfence");
}

//Measure the time taken to access the given address, in nanoseconds.
int time_access(uintptr_t ptr) {
  struct timespec ts0;
  int rc = clock_gettime(CLOCK_MONOTONIC, &ts0);
  assert(rc == 0);

  dummy += *(volatile int *) ptr;
  mfence();

  struct timespec ts;
  rc = clock_gettime(CLOCK_MONOTONIC, &ts);
  assert(rc == 0);
  return (ts.tv_sec - ts0.tv_sec) * 1000000000
         + (ts.tv_nsec - ts0.tv_nsec);
}


int timing(volatile uintptr_t* addrs,int addr_count, int bad_bit) {
  // Time memory accesses.
  int runs = 10;
  int times[runs];
  for (int run = 0; run < runs; run++) {
    // Ensure the first address is cached by accessing it.
    dummy += *(volatile int *) addrs[0];
    mfence();
    // Now pull the other addresses through the cache too.
    for (int i = 1; i < addr_count; i++) {
      dummy += *(volatile int *) addrs[i];
    }
    mfence();
    // See whether the first address got evicted from the cache by
    // timing accessing it.
    times[run] = time_access(addrs[0]);
  }

// Find the median time.  We use the median in order to discard
  // outliers.  We want to discard outlying slow results which are
  // likely to be the result of other activity on the machine.
  //
  // We also want to discard outliers where memory was accessed
  // unusually quickly.  These could be the result of the CPU's
 // eviction policy not using an exact LRU policy.
  std::sort(times, &times[runs]);
  int median_time = times[runs / 2];

  return median_time;
}


int timing_mean(volatile uintptr_t* addrs, int addr_count, int bad_bit) {
  int runs = 10;
  int sum_time = 0;
  for (int i = 0; i < runs; i++)
    sum_time += timing(addrs, addr_count, bad_bit);
  return sum_time / runs;
}

// get conflicting addresses 									
// returns virtual and physical addresses	
// for the eviction set		

int get_conflicting_address(uintptr_t start_addr, int addr_count,volatile uintptr_t *addrs, uintptr_t *phy_addrs) {
  const int page_size = 0x1000;
  uintptr_t phys1,phys2;

  addrs[0] = start_addr;
  phys1 = get_physical_addr(addrs[0]);
  phy_addrs[0] = phys1;

  uintptr_t next_addr = start_addr;
  int found = 1;
  while ((found < addr_count)) {
		if(next_addr >= end_addr)
			return 0;

    assert(next_addr < end_addr);//make sure it is with in boundary
    //uintptr_t addr = next_addr;
    next_addr += page_size;
    phys2 = get_physical_addr( next_addr);
    if (in_same_cache_set(phys1, phys2, -1)){// && (bank == bank1) && (rank == rank1)) {
      addrs[found] =  next_addr; 
      phy_addrs[found] = phys2;
      found++;
    }
  }
   
	return 1;
}


uint64_t HammerAddressesStandard(
    const std::pair<uint64_t, uint64_t>& first_range,
    const std::pair<uint64_t, uint64_t>& second_range,
    uint64_t number_of_reads, uint8_t* target_page) {
  volatile uint64_t* first_pointer =
      reinterpret_cast<uint64_t*>(first_range.first);
  volatile uint64_t* second_pointer =
      reinterpret_cast<uint64_t*>(second_range.first);
struct timespec ts0,ts;

  
	// Get conflicting addresses (eviction set)
	while(!get_conflicting_address((uintptr_t)first_pointer, size, first_addrs,phy_addr1));	
	while(!get_conflicting_address((uintptr_t)second_pointer, size, second_addrs,phy_addr2));

		// Do several trials
		printf("~~~~~~~~~~~~~~~~~~~~~~\n");
	for(int trial=0;trial<10;trial++){
		// Get start time
	 int rc = clock_gettime(CLOCK_MONOTONIC, &ts0);
         assert(rc == 0);

	// Hammer using eviction set
	for(int k=0;k<number_of_reads;k++){
			for(int j=0;j<addr_count;j++){
					dummy += *(volatile uintptr_t*)first_addrs[indexes1[j]];
					dummy2 += *(volatile uintptr_t*)second_addrs[indexes2[j]];
			}
	}

	rc = clock_gettime(CLOCK_MONOTONIC, &ts);
 assert(rc == 0);
	int total_time = (ts.tv_sec - ts0.tv_sec) * 1000000000
         + (ts.tv_nsec - ts0.tv_nsec);
	total_time/=number_of_reads;

	// Time per reads
	printf("Average time = %d ns\n",total_time);
}

return 0;
}

typedef uint64_t(HammerFunction)(
    const std::pair<uint64_t, uint64_t>& first_range,
    const std::pair<uint64_t, uint64_t>& second_range,
    uint64_t number_of_reads, uint8_t* target_add);

// A comprehensive test that attempts to hammer adjacent rows for a given 
// assumed row size (and assumptions of sequential physical addresses for 
// various rows.
uint64_t HammerAllReachablePages(uint64_t presumed_row_size, 
    void* memory_mapping, uint64_t memory_mapping_size, HammerFunction* hammer,
    uint64_t number_of_reads) {
  // This vector will be filled with all the pages we can get access to for a
  // given row size.
  std::vector<std::vector<uint8_t*>> pages_per_row;
  uint64_t total_bitflips = 0;
		uint8_t* target_add=NULL;

  pages_per_row.resize(memory_mapping_size / presumed_row_size);
  pagemap = open("/proc/self/pagemap", O_RDONLY);
  assert(pagemap >= 0);

  printf("[!] Identifying rows for accessible pages ... ");
  for (uint64_t offset = 0; offset < memory_mapping_size; offset += 0x1000) {
    uint8_t* virtual_address = static_cast<uint8_t*>(memory_mapping) + offset;
    uint64_t page_frame_number = GetPageFrameNumber(pagemap, virtual_address);
    uint64_t physical_address = page_frame_number * 0x1000;
    uint64_t presumed_row_index = physical_address / presumed_row_size;
    //printf("[!] put va %lx pa %lx into row %ld\n", (uint64_t)virtual_address,
    //    physical_address, presumed_row_index);
    if (presumed_row_index > pages_per_row.size()) {
      pages_per_row.resize(presumed_row_index);
    }
    pages_per_row[presumed_row_index].push_back(virtual_address);
    //printf("[!] done\n");
  }
  printf("Done\n");

  // We should have some pages for most rows now.
  for (uint64_t row_index = 0; row_index + 2 < pages_per_row.size(); 
      ++row_index) {
    if ((pages_per_row[row_index].size() != 64) || 
        (pages_per_row[row_index+2].size() != 64)) {
      printf("[!] Can't hammer row %ld - only got %ld/%ld pages "
          "in the rows above/below\n",
          row_index+1, pages_per_row[row_index].size(), 
          pages_per_row[row_index+2].size());
      continue;
    } else if (pages_per_row[row_index+1].size() == 0) {
      printf("[!] Can't hammer row %ld, got no pages from that row\n", 
          row_index+1);
      continue;
    }
    printf("[!] Hammering rows %ld/%ld/%ld of %ld (got %ld/%ld/%ld pages)\n", 
        row_index, row_index+1, row_index+2, pages_per_row.size(), 
        pages_per_row[row_index].size(), pages_per_row[row_index+1].size(), 
        pages_per_row[row_index+2].size());
    // Iterate over all pages we have for the first row.
    for (uint8_t* first_row_page : pages_per_row[row_index]) {
      // Iterate over all pages we have for the second row.
    for (uint8_t* second_row_page : pages_per_row[row_index+2]) {
        // Set all the target pages to 0xFF.
        for (uint8_t* target_page : pages_per_row[row_index+1]) {
          memset(target_page, 0xFF, 0x1000);
										target_add = target_page;
        }
        // Now ,target_pagehammer the two pages we care about.
        std::pair<uint64_t, uint64_t> first_page_range(
            reinterpret_cast<uint64_t>(first_row_page), 
            reinterpret_cast<uint64_t>(first_row_page+0x1000));
        std::pair<uint64_t, uint64_t> second_page_range(
            reinterpret_cast<uint64_t>(second_row_page),
            reinterpret_cast<uint64_t>(second_row_page+0x1000));
        hammer(first_page_range, second_page_range, number_of_reads,target_add);
        // Now check the target pages.
        uint64_t number_of_bitflips_in_target = 0;
        for (const uint8_t* target_page : pages_per_row[row_index+1]) {
          for (uint32_t index = 0; index < 0x1000; ++index) {
            if (target_page[index] != 0xFF) {
              ++number_of_bitflips_in_target;
            }
          }
        }
        if (number_of_bitflips_in_target > 0) {
          printf("[!] Found %ld flips in row %ld (%lx to %lx) when hammering "
              "%lx and %lx\n", number_of_bitflips_in_target, row_index+1,
              ((row_index+1)*presumed_row_size), 
              ((row_index+2)*presumed_row_size)-1,
              GetPageFrameNumber(pagemap, first_row_page)*0x1000, 
              GetPageFrameNumber(pagemap, second_row_page)*0x1000);
          total_bitflips += number_of_bitflips_in_target;
        }
      }
    }
  }
  return total_bitflips;
}

void HammerAllReachableRows(HammerFunction* hammer, uint64_t number_of_reads) {
  size_t mapping_size;
  void* mapping;
  SetupMapping(&mapping_size, &mapping);

  HammerAllReachablePages(1024*256, mapping, mapping_size,
                          hammer, number_of_reads);
}

void HammeredEnough(int sig) {
  printf("[!] Spent %ld seconds hammering, exiting now.\n",
      number_of_seconds_to_hammer);
  fflush(stdout);
  fflush(stderr);
  exit(0);
}

int main(int argc, char** argv) {
  // Turn off stdout buffering when it is a pipe.
  setvbuf(stdout, NULL, _IONBF, 0);

  int opt;
  while ((opt = getopt(argc, argv, "t:p:")) != -1) {
    switch (opt) {
      case 't':
        number_of_seconds_to_hammer = atoi(optarg);
        break;
      case 'p':
        fraction_of_physical_memory = atof(optarg);
        break;
      default:
        fprintf(stderr, "Usage: %s [-t nsecs] [-p percent]\n", 
            argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  signal(SIGALRM, HammeredEnough);

  printf("[!] Starting the testing process...\n");
  alarm(number_of_seconds_to_hammer);
  HammerAllReachableRows(&HammerAddressesStandard, number_of_reads);
}

