#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


/*---- Defines for table processing ----*/
#define OFFSET_MASK        0xFFFLU
#define TABLE_MASK         0x1FFLU << 12
#define DIRECTORY_MASK     0x1FFLU << 21
#define DIRECTORY_PTR_MASK 0x1FFLU << 30
#define PML4_MASK          0x1FFLU << 39

/*---- Define for table values processing ----*/
#define PHYSICAL_ADDRES_MASK_SHIFT 12
#define PHYSICAL_ADDRES_MASK       0xFFFFFFFFFFLU << PHYSICAL_ADDRES_MASK_SHIFT


typedef struct table_entry {
    uint64_t paddr;
    uint64_t value;
} table_entry;


/*---- Tables processing ----*/
uint64_t get_table_shift(uint64_t logic_address,
                         uint64_t logic_address_level) {
    return (logic_address & logic_address_level)*8;
}

uint64_t get_addr_of_table1_val(uint64_t logic_address,
                             uint64_t table1_address) {
    return table1_address + (get_table_shift(logic_address, PML4_MASK) >> 39);
}

uint64_t get_addr_of_table2_val(uint64_t logic_address,
                              uint64_t table2_address) {
    return table2_address + (get_table_shift(logic_address, DIRECTORY_PTR_MASK) >> 30);
}

uint64_t get_addr_of_table3_val(uint64_t logic_address,
                             uint64_t table3_address) {
    return table3_address + (get_table_shift(logic_address, DIRECTORY_MASK) >> 21);
}

uint64_t get_addr_of_table4_val(uint64_t logic_address,
                              uint64_t table4_address) {
    return table4_address + (get_table_shift(logic_address, TABLE_MASK) >> 12);
}

uint64_t get_addr_of_phys_page_val(uint64_t logic_address,
                               uint64_t phys_page_address) {
    return phys_page_address + (logic_address & OFFSET_MASK);
}

/*---- Table values processing ----*/
uint64_t get_phys_addr_from_tab_val(uint64_t table_val) {
    return (table_val & PHYSICAL_ADDRES_MASK);
}

bool entry_is_used(uint64_t table_val) {
    return table_val & 0x01;
}

uint64_t find_val_by_addr(table_entry *table_entries, uint32_t m, uint64_t addr) {
    uint64_t finding_value = 0;
    for(size_t j = 0; j < m; ++j) {
        if(table_entries[j].paddr == addr) {
            finding_value = table_entries[j].value;
            break;
        }
    }
    return finding_value;
}


int main()
{
    FILE* input;
    FILE *output;
    uint32_t m;
    uint64_t q;
    uint64_t r;
    table_entry *table_entries;
    uint64_t *logical_addresses;

    input = fopen("dataset_44327_15.txt", "r");
    output = fopen("result.txt", "w");
    if(input == NULL || output == NULL)
        return 1;
 
    fscanf(input, "%u%lu%lu", &m, &q, &r);
    
    table_entries = malloc(m * sizeof(table_entry));
    for(size_t i = 0; i < m; ++i) {
        fscanf(input, "%lu%lu", &table_entries[i].paddr, &table_entries[i].value);
    }

    logical_addresses = malloc(q * sizeof(uint64_t));
    for(size_t i = 0; i < q; ++i) {
        fscanf(input, "%lu", &logical_addresses[i]);
    }

    fclose(input);


    uint64_t curr_table_base_addr = 0;
    for(size_t i = 0; i < q; ++i) {
        curr_table_base_addr = r;
        uint64_t curr_addr = get_addr_of_table1_val(logical_addresses[i],
                                           curr_table_base_addr);

        uint64_t finding_value = find_val_by_addr(table_entries, m, curr_addr);
        if(finding_value == 0 ||
           !entry_is_used(finding_value)) {
            fprintf(output, "fault\n");
            continue;
        }
        //printf("%lu\n", finding_value);

        curr_table_base_addr = get_phys_addr_from_tab_val(finding_value);
        curr_addr = get_addr_of_table2_val(logical_addresses[i],
                                           curr_table_base_addr);

        finding_value = find_val_by_addr(table_entries, m, curr_addr);
        if(finding_value == 0 ||
           !entry_is_used(finding_value)) {
            fprintf(output, "fault\n");
            continue;
        }
        //printf("%lu\n", finding_value);

        curr_table_base_addr = get_phys_addr_from_tab_val(finding_value);
        curr_addr = get_addr_of_table3_val(logical_addresses[i],
                                           curr_table_base_addr);

        finding_value = find_val_by_addr(table_entries, m, curr_addr);
        if(finding_value == 0 ||
           !entry_is_used(finding_value)) {
            fprintf(output, "fault\n");
            continue;
        }
        //printf("%lu\n", finding_value);

        curr_table_base_addr = get_phys_addr_from_tab_val(finding_value);
        curr_addr = get_addr_of_table4_val(logical_addresses[i],
                                           curr_table_base_addr);

        finding_value = find_val_by_addr(table_entries, m, curr_addr);
        if(finding_value == 0 ||
           !entry_is_used(finding_value)) {
            fprintf(output, "fault\n");
            continue;
        }
        //printf("%lu\n", finding_value);

        curr_table_base_addr = get_phys_addr_from_tab_val(finding_value);
        curr_addr = get_addr_of_phys_page_val(logical_addresses[i],
                                              curr_table_base_addr);

        finding_value =(curr_addr);
        fprintf(output, "%lu\n", finding_value);
    }


    //printf("m: %u\nq: %lu\nr: %lu\n", m, q, r);
    //for(size_t i = 0; i < m; ++i) {
    //    printf("%lu %lu\n", table_entries[i].paddr, table_entries[i].value);
    //}
    //for(size_t i = 0; i < q; ++i) {
    //    printf("%lu\n", logical_addresses[i]);
    //}

    fclose(output);
    free(table_entries);
    free(logical_addresses);
    return 0;
}
