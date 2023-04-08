#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


#define ENTRY_VALID_BIT_MASK 0b01LU
#define PHYSICAL_ADDRESS_SHIFT 12
#define PHYSICAL_ADDRESS_MASK (0xFFFFFFFFFFLU << PHYSICAL_ADDRESS_SHIFT)


enum LEVEL_TYPE {
    PML4,
    DIRECTORY_PTR,
    DIRECTORY,
    TABLE,
    PHYS_SEGMENT
};

enum LEVEL_SHIFTS {
    PML4_SHIFT=39,
    DIRECTORY_PTR_SHIFT=30,
    DIRECTORY_SHIFT=21,
    TABLE_SHIFT=12
};

enum LEVEL_MASKS {
    PML4_MASK = (0x1FFLU<<PML4_SHIFT),
    DIRECTORY_PTR_MASK = (0x1FFLU<<DIRECTORY_PTR_SHIFT),
    DIRECTORY_MASK = (0x1FFLU<<DIRECTORY_SHIFT),
    TABLE_MASK = (0x1FFLU<<TABLE_SHIFT),
    OFFSET_MASK = 0xFFF
};


struct table_entry {
    uint64_t paddr;
    uint64_t value;
};


uint8_t init(char input_file[],
             uint32_t *table_entries_num,
             uint64_t *queries_num,
             uint64_t *root_tab_base,
             uint64_t *queries[],
             struct table_entry *table_entries[]);

uint64_t get_tab_entry_addr(uint64_t logical_addr,
                           uint64_t curr_tab_base,
                           enum LEVEL_TYPE tab_type);

uint64_t find_val_by_addr(uint64_t addr, struct table_entry *table_entries, uint32_t table_entries_num);


int main()
{
    FILE *output;
    uint32_t table_entries_num;
    uint64_t queries_num;
    uint64_t root_tab_base;
    uint64_t *queries;
    struct table_entry *table_entries;
    

    if(!init("test/dataset_44327_15.txt",
             &table_entries_num,
             &queries_num,
             &root_tab_base,
             &queries,
             &table_entries)) {
        return 1;
    }


    output = fopen("test/result.txt", "w");
    if(output == NULL) {
        return 1;
    }
    uint64_t tab_base = 0;
    struct table_entry tab_entry = {0, 0};
    enum LEVEL_TYPE table_levels[] = {PML4, DIRECTORY_PTR, DIRECTORY, TABLE, PHYS_SEGMENT};
    const uint8_t LEVELS = sizeof(table_levels)/sizeof(enum LEVEL_TYPE);

    for(size_t i = 0; i < queries_num; ++i) {
        tab_base = root_tab_base;
        for(size_t level = 0; level < LEVELS; ++level) {
            tab_entry.paddr = get_tab_entry_addr(queries[i], tab_base, table_levels[level]);
            if(level == LEVELS-1) {
                fprintf(output, "%lu\n", tab_entry.paddr);
                break;
            }

            tab_entry.value = find_val_by_addr(tab_entry.paddr, table_entries, table_entries_num);
            if((tab_entry.value & ENTRY_VALID_BIT_MASK) == 0) {
                fprintf(output, "fault\n");
                break;
            }

            tab_base = tab_entry.value & PHYSICAL_ADDRESS_MASK;
        }
    }


    fclose(output);
    free(queries);
    free(table_entries);
    return 0;
}


uint8_t init(char input_file[],
             uint32_t *table_entries_num,
             uint64_t *queries_num,
             uint64_t *root_tab_base,
             uint64_t *queries[],
             struct table_entry *table_entries[]) {
    FILE *input;
    input = fopen(input_file, "r");
    if(input == NULL)
        return 0;

    fscanf(input, "%u%lu%lu",
           table_entries_num,
           queries_num,
           root_tab_base);
    
    *table_entries = malloc(*table_entries_num * sizeof(struct table_entry));
    for(size_t i = 0; i < *table_entries_num; ++i) {
        fscanf(input, "%lu%lu", &(*table_entries)[i].paddr, &(*table_entries)[i].value);
    }

    *queries = malloc(*queries_num * sizeof(uint64_t));
    if(queries == NULL) {
        exit(1);
    }
    for(size_t i = 0; i < *queries_num; ++i) {
        fscanf(input, "%lu", &(*queries)[i]);
    }

    fclose(input);

    return 1;
}

uint64_t get_tab_entry_addr(uint64_t logical_addr,
                            uint64_t curr_tab_base,
                            enum LEVEL_TYPE tab_type) {
    uint64_t tab_entry_addr = 0;
    
    switch(tab_type) {
    case PML4:
        tab_entry_addr = curr_tab_base + ((logical_addr & PML4_MASK)>>PML4_SHIFT)*8;
        break;
    case DIRECTORY_PTR:
        tab_entry_addr = curr_tab_base + ((logical_addr & DIRECTORY_PTR_MASK)>>DIRECTORY_PTR_SHIFT)*8;
        break;
    case DIRECTORY:
        tab_entry_addr = curr_tab_base + ((logical_addr & DIRECTORY_MASK)>>DIRECTORY_SHIFT)*8;
        break;
    case TABLE:
        tab_entry_addr = curr_tab_base + ((logical_addr & TABLE_MASK)>>TABLE_SHIFT)*8;
        break;
    case PHYS_SEGMENT:
        tab_entry_addr = curr_tab_base + (logical_addr & OFFSET_MASK);
        break;
    }

    return tab_entry_addr;
}

uint64_t find_val_by_addr(uint64_t addr, struct table_entry *table_entries, uint32_t table_entries_num) {
    for(size_t i = 0; i < table_entries_num; ++i) {
        if(table_entries[i].paddr == addr) {
            return table_entries[i].value;
        }
    }

    return 0;
}
