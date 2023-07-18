# Description for pintool usage
This is a collection of self-written pintools mainly used for the [Value Prediction study](https://github.com/haiyuem/Value-Prediction-for-Input-Data-Commonality), but might be adapted for future use in other studies. 

7/18/2023: Updated script to also use for value locality detector. 

## Programs:
- **count_unique_ins**: Print out all RTNs and then all the different op types used for instructions, one op once. Used to determine what ops are encountered to translate when generating a CVP trace. 
- **print_ins**: Print out all ins in specified RTN; if no RTN specified, will print out all insts
- **read_memval_ins**: Print out all insts that are mem reads and the read value
- **same_ins_load_pattern**: For the first MAX_INS_COUNT load insts, the program prints out everytime it executes, and the mem addr loaded, and the value
- **write_out_trace**: Write out CVP friendly binary trace. 
	- Split Intel64 fused insts (LD/ST + ALU) into two separate insts with the same PC
	- In code, change "*print_ins*" to true to print out inst stream; change "*print*" to true to print out inst details as required by CVP traces (1-1 map in human-readable format)

- **write_load_addr_val**: New script used to generate trace for profiling data value locality in programs. See file for documentation.


## Arguments: 
- -o: output file name
- -rtn_name_to_parse: Pass in RTN name to parse, can match partially, exists in all codes
- -trace (only in write_out_trace): trace name to write out to
