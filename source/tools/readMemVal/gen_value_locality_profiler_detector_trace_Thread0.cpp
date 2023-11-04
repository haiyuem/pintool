/*
 *    Copyright 2023 The ChampSim Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*! @gen_value_locality_profiler_detector_trace_Thread0
 *  This file generates:
 *  1) a trace of all memory accesses and their values "loadval" for the Value Locality Profiler; both .csv (human-readble) and .trace (binary) formats
 *  2) a trace of all non-memory operands and their values "operandval" for the Value Locality Profiler; both .csv (human-readble) and .trace (binary) formats
 *  3) a trace of all instructions for the ChampSim simulator. (*scheduler.trace)
 *  4) a debug file that prints out human friendly info of each instruction. (*trace.debug)
 */

/*******************************Change Logs**********************************/
/*
 * 05/04/2023 HM: Add support to dump specific RTN and all the instructions called within the RTN 
 * Add support to write operand values for each instruction into trace 
 * Trace format: [original instruction][op1(64bit)][op2(64bit)][op3(64bit)][op4(64bit)]
 * value=0xdeadbeef means it's not a valid operand
 *
 * 07/06/2023 HM: Fixed issue for reading value, now reads all instruction's operand values (max 4)
 * Differentiated regular 64-bits operands and xmm reg operands (4*32-bit single-precision FP), but still uses (first) 64 bits for now, need to change 
 * TODO: 1) separate regular and xmm operands  2) include mem load/store values (need to add a field in champsim)

 * 07/18/2023 HM: Only focusing on regular 64-bit registers and xmm registers (but the first 32 bits), ignoring all other types of regs for now, need to add later 

 * 07/21/2023 HM: make the code PIN thread-safe 

 * 07/24/2023 HM: merge gen_cluster_trace and gen_champsim_trace

 * 07/25/2023 HM: realized that the simpoint result is per thread, add thread inst count for thread 0 for shouldwrite

 * 07/26/2023 HM: Change this file to single thread (only track T0) to speed up for single thread apps

 * 08/04/2023 HM: Differentiate different sizes of mem loads and non-mem operands, output the size for pie-chart and type-specific value locality detection

 * 11/03/2023 HM: Restruture the code, generate .csv and binary traces simultaneously, add feature of tracing unique operand values, hide output file for different operand value types (can be enabled with command line options)
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <atomic>
#include <unordered_map>
#include "regvalue_utils.h"

#include <cstring>
#include <sstream>
#include <array>
#include <fstream>
#include <string>

#include "/scratch/gpfs/hm2595/champsim-datacomm/inc/trace_instruction.h"

using namespace std;

using trace_instr_format_t = datacomm_instr;

atomic<int> activeThreadCount(0);

/* ================================================================== */
// Global variables 
/* ================================================================== */

// This map stores what operation it is for the last access of the mem address, for detecting silent store
unordered_map<ADDRINT, char> memaddr_last_operation;
unordered_map<REG, char> reg_last_operation;

// gen 3 traces: loadval/operandval_outfile to be processed by the Python value locality profiler, scheduler_outfile to be processed in champsim (hardware scheduler)
const size_t TRACE_SUFFIXES_SIZE = 2;
const size_t TRACE_DIFFSIZE_SUFFIXES_SIZE = 5;

ofstream scheduler_outfile;
string trace_suffixes[2] = {"", ".csv"};
ofstream loadval_outfiles[2]; 
ofstream operandval_outfiles[2];
ofstream debugfile; //debug file that prints out the instructions in a human-readable form

// separate output files for different data types of operand values. Off by default, need to add command line option (-op_type) to enable
string trace_diffsize_suffixes[5] = {"_8bit", "_16bit", "_32bit", "_64bit", "_above64bit"}; 
ofstream operandval_outfiles_diffsize[5]; 

// count the number of instructions
UINT64 progInstrCount; // global count of the application, regardless of any limitation
UINT64 tracedInstrCount; // count of the instructions that are traced
UINT64 memReadCount; // count of the memory reads that are traced

trace_instr_format_t curr_instr;
bool should_write = false; // Whether this instruction needs to be written out
bool should_write_memread = false; // only applies to mem reads; for cluster trace

// memread size counter: this includes middle sizes: size 8 = size <=8bits, size 16 = 8 < size <= 16, etc
UINT32 memread_size_counter[TRACE_DIFFSIZE_SUFFIXES_SIZE] = {0, 0, 0, 0, 0};

// reg size counter
UINT32 reg_size_counter[TRACE_DIFFSIZE_SUFFIXES_SIZE] = {0, 0, 0, 0, 0};

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobSchedulerOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "scheduler_trace_output", "scheduler.trace", 
        "specify file name for Champsim tracer output (to test the scheduler)");
KNOB<string> KnobLoadValOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "profiler_loadval_trace_output", "profiler_loadval.trace", 
        "specify file name for load values tracer output");
KNOB<string> KnobOperandValOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "profiler_operandval_trace_output", "profiler_operandval.trace", 
        "specify file name for operand values tracer output");

// Whether to print out individual data size operand val trace
KNOB<bool> KnobOperandValDiffDataSizeOutput(KNOB_MODE_WRITEONCE, "pintool", "produce_individual_trace_for_data_size", "0", 
        "Whether to print out individual data size operand val trace");

// Whether to print out debug file
KNOB<bool> KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "d", "0", 
        "Whether to print out debug info in another file");
KNOB<string> KnobDebugFile(KNOB_MODE_WRITEONCE,  "pintool", "debug_file_name", "trace.debug", 
        "specify file name for Champsim tracer human-readable output for debugging");

// TODO: merge cluster_gen's interval and jump mechanisms here
KNOB<UINT64> KnobSkipInstructions(KNOB_MODE_WRITEONCE, "pintool", "s", "0", 
        "How many instructions to skip before tracing begins");
KNOB<UINT64> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "ti", "0", 
        "How many instructions to trace");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool creates a register and memory access trace" << endl 
        << "Specify the ChampSim output trace file (for scheduler) with -champsim_trace_output" << endl 
        << "Specify the load values output trace file with -cluster_trace_output" << endl 
        << "Specify the operand values output trace file with -operand_val_trace_output" << endl 
        << "Specify whether to print out individual data size operand val trace with -produce_individual_trace_for_data_size" << endl
        << "Specify whether to print out to print out debug info in another file with -d" << endl
        << "Specify the debug file name with -debug_file_name" << endl
        << "Specify the number of instructions to skip before tracing with -s" << endl
        << "Specify the number of instructions to trace with -t; default = 0 means no upper limit" << endl 
        // << "Specify the RTN name to parse with -rtn_name_to_parse" << endl
        << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
// Debug: prints out instructions and verbose info
/* ===================================================================== */
void Debug(ADDRINT pc, const string ins_str, BOOL is_memoryread)
{
    if (should_write && (PIN_ThreadId() == 0)){
        stringstream message;
        message << dec << " Ins Count: " << progInstrCount << " " << "Traced Ins Count: " << tracedInstrCount << " " << hex << "PC: " << pc << " " << ins_str ;
        if (should_write_memread) message << " Mem Count: " << dec << memReadCount;
        message << endl;
        for (unsigned int nth_reg=0; nth_reg<NUM_INSTR_SOURCES; nth_reg++){
            REG r = (REG)(curr_instr.source_registers[nth_reg]);
            if (REG_valid(r)){
                message << dec << "Reg: " << REG_StringShort((REG)(curr_instr.source_registers[nth_reg])) << " Val: " << hex << curr_instr.operand_vals[nth_reg] << endl;
            }
        }
        // write all at once
        debugfile << message.str();
    }
}

//This is to count the number of ins
VOID ShouldWrite(BOOL is_memoryread){
    // global count of the application, regardless of any limitation
    if (PIN_ThreadId() == 0) {
        should_write = false;
        should_write_memread = false;
        ++progInstrCount;
        if (KnobTraceInstructions.Value() == 0) {
            should_write = (progInstrCount > KnobSkipInstructions.Value());
        }
        else {
            // quit if the program has run past the tracing range
            if ((progInstrCount > (KnobTraceInstructions.Value() + KnobSkipInstructions.Value())))
                PIN_ExitApplication(0);
            should_write = (progInstrCount > KnobSkipInstructions.Value());
        }
        if (should_write){
            ++tracedInstrCount;
            // if this is memory read, this is traced by cluster trace gen
            should_write_memread = is_memoryread;
            if (should_write_memread) {
                ++memReadCount;
            }
        }
    }
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

void ResetCurrentInstruction(VOID *ip)
{
    if (should_write && (PIN_ThreadId() == 0)){
        curr_instr = {};
        curr_instr.ip = (unsigned long long int)ip;
    }
}

// Processes the operand values of the current instruction and writes it to the trace file
void WriteCurrentInstruction()
{
    // Note: this function now writes out operand value traces for all instructions, including memory reads. In ChampSim, mem reads are not processed in the same way as other instructions, and only the non-memory operand values are used. However in many pipelines operand values of mem reads should also go through ALU so they need to be included.
    // TODO: Still need to debate whether we should take memory reads outside the traces. 
    if (should_write && (PIN_ThreadId() == 0)){
        // write scheduler output file for champsim
        typename decltype(scheduler_outfile)::char_type buf[sizeof(trace_instr_format_t)];
        memcpy(buf, &(curr_instr), sizeof(trace_instr_format_t));
        scheduler_outfile.write(buf, sizeof(trace_instr_format_t)); 

        // update operand value Read/Store history map, and update if the first operand is from a different source
        bool op_is_diff_source = true;
        for (unsigned int nth_reg=0; nth_reg<NUM_INSTR_SOURCES; nth_reg++){
            REG r = (REG)(curr_instr.source_registers[nth_reg]);
            if (REG_valid(r)){
                auto it = reg_last_operation.find(r);
                if ((nth_reg == 0) && (it != reg_last_operation.end()) && (it->second == 'R')) {
                    op_is_diff_source = false;
                }
                reg_last_operation[r] = 'R';
            }
        }
        for (unsigned int nth_reg=0; nth_reg<NUM_INSTR_DESTINATIONS; nth_reg++){
            REG r = (REG)(curr_instr.destination_registers[nth_reg]);
            if (REG_valid(r)){
                reg_last_operation[r] = 'S';
            }
        }


        // write operand val trace for hardware detector
        //['Index', 'PC', 'Reg Name'(not important), 'Data Value', 'Is Unique', 'Reg Width']
        // only print when the first read reg exists
        if ((REG)(curr_instr.source_registers[0]) != REG_INVALID()){
            //count different types of reg size 
            UINT8 reg_width = REG_Width((REG)(curr_instr.source_registers[0]));
            if (reg_width == REGWIDTH_8 ) reg_size_counter[0]++;
            else if (reg_width == REGWIDTH_16 ) reg_size_counter[1]++;
            else if (reg_width == REGWIDTH_32 ) reg_size_counter[2]++;
            else if (reg_width == REGWIDTH_64 ) reg_size_counter[3]++;
            else reg_size_counter[4]++;

            // write operand val, only take the first 64 bits of the first one for now
            // size of each element in bytes: 8, 8, 1, 8, 1, 1
            // Create a buffer to hold all the data.
            char buffer[sizeof(tracedInstrCount) + sizeof(curr_instr.ip) 
                        + sizeof(curr_instr.source_registers[0]) 
                        + sizeof(curr_instr.operand_vals[0])
                        + sizeof(op_is_diff_source)
                        + sizeof(reg_width)];

            // Use memcpy to copy data to the buffer.
            char* dest = buffer;

            memcpy(dest, &tracedInstrCount, sizeof(tracedInstrCount));
            dest += sizeof(tracedInstrCount);
            memcpy(dest, &(curr_instr.ip), sizeof(curr_instr.ip));
            dest += sizeof(curr_instr.ip);
            memcpy(dest, &(curr_instr.source_registers[0]), sizeof(curr_instr.source_registers[0]));
            dest += sizeof(curr_instr.source_registers[0]);
            memcpy(dest, &(curr_instr.operand_vals[0]), sizeof(curr_instr.operand_vals[0]));
            dest += sizeof(curr_instr.operand_vals[0]);
            memcpy(dest, &op_is_diff_source, sizeof(op_is_diff_source));
            dest += sizeof(op_is_diff_source);
            memcpy(dest, &reg_width, sizeof(reg_width));
            dest += sizeof(reg_width);

            if (!KnobOperandValDiffDataSizeOutput.Value()){
                operandval_outfiles[0].write(buffer, sizeof(buffer));
            } else {
                if (reg_width == REGWIDTH_8) { operandval_outfiles_diffsize[0].write(buffer, sizeof(buffer)); }
                else if (reg_width == REGWIDTH_16) { operandval_outfiles_diffsize[1].write(buffer, sizeof(buffer)); }
                else if (reg_width == REGWIDTH_32) { operandval_outfiles_diffsize[2].write(buffer, sizeof(buffer)); }
                else if (reg_width == REGWIDTH_64) { operandval_outfiles_diffsize[3].write(buffer, sizeof(buffer)); }
                else { operandval_outfiles_diffsize[4].write(buffer, sizeof(buffer)); }
            }

            
            // operandval_outfile.write((char*)(&tracedInstrCount), sizeof(tracedInstrCount));
            // operandval_outfile.write((char*)(&(curr_instr.ip)), sizeof(curr_instr.ip));
            // operandval_outfile.write((char*)(&(curr_instr.source_registers[0])), sizeof(curr_instr.source_registers[0]));
            // operandval_outfile.write((char*)(&(curr_instr.operand_vals[0])), sizeof(curr_instr.operand_vals[0]));
            // operandval_outfile.write((char*)(&reg_width), sizeof(reg_width));

            operandval_outfiles[1] << dec << tracedInstrCount << ", " << (UINT64)(curr_instr.ip) << ", " << (UINT64)(curr_instr.source_registers[0]) << ", " << (UINT64)(curr_instr.operand_vals[0]) << ", " << (int)op_is_diff_source << ", " << (int)reg_width << endl;
        }
    }
}

void BranchOrNot(UINT32 taken)
{
    if (should_write && (PIN_ThreadId() == 0)){
        curr_instr.is_branch = 1;
        curr_instr.branch_taken = taken;
    }
}

//This function was used to put a reg/memop into a list
//WriteValToSet writes both reg names and vals; original WriteToSet func only works for mem ops (no vals for now, might add later)
// Use PIN_GetContextRegval (more flexible, can be used as long as we have context)
void WriteValToSet(unsigned char* begin, unsigned char* end, UINT32 r, CONTEXT* ctxt, REG reg, bool is_source_reg)
{
    if (should_write && (PIN_ThreadId() == 0)){
        auto set_end = find(begin, end, 0);
        auto found_reg = find(begin, set_end, r); // check to see if this register is already in the list
        // If the register is not found in the list, insert it
        int nth_reg = distance(begin, found_reg);

        *found_reg = r;

        // Uses PINTOOL_REGISTER from util, can hold any reg size, can interpret with different sizes
        PINTOOL_REGISTER val;
        PIN_GetContextRegval(ctxt, reg, reinterpret_cast< UINT8* >(&val));
        // only write to operand_vals for source registers
        if (is_source_reg) curr_instr.operand_vals[nth_reg] = val.qword[0];
    }
}

void WriteToSet(unsigned long long int* begin, unsigned long long int* end, ADDRINT r)
{
    if (should_write && (PIN_ThreadId() == 0)){
        auto set_end = find(begin, end, 0);
        auto found_reg = find(begin, set_end, r); // check to see if this register is already in the list
        *found_reg = r;
    }
}

void WriteImmediate(UINT64 immediate){
    if (should_write && (PIN_ThreadId() == 0)){
        curr_instr.operand_vals[3] = immediate; 
    }
}

// ++++++++++++++++++++++++++++++++++++++++++
// gen cluster trace:
// ++++++++++++++++++++++++++++++++++++++++++
VOID ReadContent(ADDRINT ins_addr, VOID* memread_addr, UINT32 memread_size, const string ins_str)
{
    if (should_write_memread && (PIN_ThreadId() == 0)){
        UINT64 value = 0;
        // global counters for mem read size: 
        UINT8 memread_size_type = 4; // 0,1,2,3,4 for 8,16,32,64,>64, default >64
        if (memread_size <= 1) {memread_size_counter[0]++; memread_size_type=0;}
        else if (memread_size <= 2) {memread_size_counter[1]++; memread_size_type=1;}
        else if (memread_size <= 4) {memread_size_counter[2]++; memread_size_type=2;}
        else if (memread_size <= 8) {memread_size_counter[3]++; memread_size_type=3;}
        else memread_size_counter[4]++;
        
        // this is to prevent bigger memread_size to cause seg faults - e.g. context switch instructions can have 380 bytes memread_size and it will cause false PCs
        UINT32 memread_size_cut = memread_size;
        if (memread_size_cut > 8) memread_size_cut = 8;
        size_t read_size = PIN_SafeCopy((VOID*)(&value), (VOID*)memread_addr, memread_size_cut);
        assert(read_size == (size_t)memread_size_cut);
        // Align with cache line size 
        ADDRINT memread_addr1 = (ADDRINT)memread_addr - ((ADDRINT)memread_addr % 64);

        //check whether it's a load of different source
        bool load_is_diff_source = true;
        
        auto it = memaddr_last_operation.find((ADDRINT)memread_addr1);
        // Write down current op = Read
        memaddr_last_operation[memread_addr1] = 'R';

        if (it != memaddr_last_operation.end()){
            if(it->second == 'R') {
                load_is_diff_source = false;
            }
        }

        // Create a buffer to hold all the data. The size of each element in bytes is:
        // 8 (for memReadCount) + 8 (for ins_addr) + 8 (for memread_addr) + 8 (for value) + 
        // 1 (for load_is_diff_source) + 1 (for memread_size_type) = 26 bytes.
        char buffer[sizeof(tracedInstrCount) + sizeof(curr_instr.ip) 
                        + sizeof(curr_instr.source_registers[0]) 
                        + sizeof(curr_instr.operand_vals[0])
                        + sizeof(load_is_diff_source)
                        + sizeof(memread_size_type)];
        char* dest = buffer;

        // Use memcpy to copy data to the buffer.
        memcpy(dest, &memReadCount, sizeof(memReadCount));
        dest += sizeof(memReadCount);
        memcpy(dest, &ins_addr, sizeof(ins_addr));
        dest += sizeof(ins_addr);
        memcpy(dest, &memread_addr, sizeof(memread_addr));
        dest += sizeof(memread_addr);
        memcpy(dest, &value, sizeof(value));
        dest += sizeof(value);
        memcpy(dest, &load_is_diff_source, sizeof(load_is_diff_source));
        dest += sizeof(load_is_diff_source);
        memcpy(dest, &memread_size_type, sizeof(memread_size_type));
        // dest += sizeof(memread_size_type); // This line is not needed as it's the last item.

        // Write the buffer to the file in one call.
        loadval_outfiles[0].write(buffer, sizeof(buffer));

        loadval_outfiles[1] << dec << memReadCount << ", " << (UINT64)ins_addr << ", " << (UINT64)memread_addr << ", " << value << ", " << load_is_diff_source << ", " << (int)memread_size_type << endl;
    }
}

// Just record the memory address of the store - will check if it's silent store in the Python code 
VOID RecordWriteAddr(ADDRINT memwrite_addr) {
    if (should_write && (PIN_ThreadId() == 0)){
        memwrite_addr = memwrite_addr - (memwrite_addr % 64);
        memaddr_last_operation[memwrite_addr] = 'S'; 
    }
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

// Is called for every instruction and instruments reads and writes
// VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
VOID Instruction(INS ins, VOID* v)
{
    // Count insts + check if this ins needed to be written
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ShouldWrite, IARG_BOOL, INS_IsMemoryRead(ins),IARG_END);

    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ResetCurrentInstruction, IARG_INST_PTR, IARG_END);

    // instrument branch instructions
    // TODO: temporarily exclude xbegin/xend instructions since IARG_BRANCH_TAKEN currently doesn't support that
    if(INS_IsBranch(ins) && (INS_Disassemble(ins).find("xend") == string::npos) && (INS_Disassemble(ins).find("xbegin") == string::npos)){
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_END);
    }

    // instrument register reads
    UINT32 readRegCount = INS_MaxNumRRegs(ins);
    for(UINT32 i=0; i<readRegCount; i++) 
    {
        
        if (!REG_is_flags(INS_RegR(ins, i))){
            UINT32 regNum = INS_RegR(ins, i);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteValToSet,
            IARG_PTR, curr_instr.source_registers, IARG_PTR, curr_instr.source_registers + NUM_INSTR_SOURCES,
            IARG_UINT32, regNum, 
            IARG_CONTEXT,
            IARG_ADDRINT, regNum,
            IARG_BOOL, true,
            IARG_END);
        }
    }

    // instrument register writes
    UINT32 writeRegCount = INS_MaxNumWRegs(ins);  
    for(UINT32 i=0; i<writeRegCount; i++) 
    {
        UINT32 regNum = INS_RegW(ins, i);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteValToSet,
            IARG_PTR, curr_instr.destination_registers, IARG_PTR, curr_instr.destination_registers + NUM_INSTR_DESTINATIONS,
            IARG_UINT32, regNum, 
            IARG_CONTEXT,
            IARG_ADDRINT, regNum,
            IARG_BOOL, false,
            IARG_END);
    }

    // instrument immediate values
    INT32 opcount = INS_OperandCount(ins);
    for (INT32 i = 0; i < opcount; i++){
        if (INS_OperandIsImmediate(ins, i)){
            // ADDRINT value     = INS_OperandImmediate(ins, i);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteImmediate,
                IARG_UINT64, INS_OperandImmediate(ins, i),
                IARG_END);
        }
    }

    // instrument memory reads and writes
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) 
    {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet,
                IARG_PTR, curr_instr.source_memory, IARG_PTR, curr_instr.source_memory + NUM_INSTR_SOURCES,
                IARG_MEMORYOP_EA, memOp, IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, memOp)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet,
                IARG_PTR, curr_instr.destination_memory, IARG_PTR, curr_instr.destination_memory + NUM_INSTR_DESTINATIONS,
                IARG_MEMORYOP_EA, memOp, IARG_END);
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++
    // gen cluster trace: 
    if (INS_IsMemoryRead(ins) && (!INS_IsPrefetch(ins)) && (INS_Disassemble(ins).find("gather") == string::npos) && (INS_Opcode(ins) != XED_ICLASS_TILELOADD)){
        INS_InsertCall(ins,
            IPOINT_BEFORE,
            AFUNPTR(ReadContent),
            IARG_INST_PTR,
            IARG_MEMORYREAD_EA,
            IARG_MEMORYREAD_SIZE, 
            //IARG_REG_VALUE,
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_END);
    } 
    if (INS_IsMemoryWrite(ins) && (INS_Disassemble(ins).find("scatter") == string::npos) && (INS_Opcode(ins) != XED_ICLASS_TILESTORED) && INS_IsValidForIpointAfter(ins)) { // Mark silent stores
        INS_InsertCall(ins,
            IPOINT_BEFORE,
            (AFUNPTR)RecordWriteAddr,
            IARG_MEMORYWRITE_EA,
            IARG_END);
    }
    // ++++++++++++++++++++++++++++++++++++++++++

    // finalize each instruction with this function, write out operand values file
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteCurrentInstruction, IARG_END);
    
    //Debug function that prints out instructions in a readable form
    if (KnobDebug.Value()){
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Debug, 
        IARG_INST_PTR,
        IARG_PTR, new string(INS_Disassemble(ins)), //print out instruction string for debug
        IARG_BOOL, INS_IsMemoryRead(ins),
        IARG_END);
    }      
}


/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    debugfile << "======================================================" << endl;
    // print out ins count
    debugfile << dec << "Total Inst Count: " << progInstrCount << " Traced Inst Count: " << tracedInstrCount << " Mem Count: " << memReadCount << endl;
    //print out pie chart for mem read size counts
    debugfile << "memreadsize,8,16,32,64,above" << endl;
    debugfile << memread_size_counter[0] << "," << memread_size_counter[1] << "," << memread_size_counter[2] << "," << memread_size_counter[3] << "," << memread_size_counter[4] << endl;
    //print out pie chart for non-mem operand size counts
    debugfile << "regsize,8,16,32,64,above" << endl;
    debugfile << reg_size_counter[0] << "," << reg_size_counter[1] << "," << reg_size_counter[2] << "," << reg_size_counter[3] << "," << reg_size_counter[4] << endl;

    if (scheduler_outfile.is_open()) scheduler_outfile.close();
    vector<string> suffixes = {"", ".csv"};
    for (size_t i = 0; i < TRACE_SUFFIXES_SIZE; ++i) {
        if (loadval_outfiles[i].is_open()) loadval_outfiles[i].close();
        if (operandval_outfiles[i].is_open()) operandval_outfiles[i].close();
    }
    vector<string> diffsize_suffixes = {"_8bit", "_16bit", "_32bit", "_64bit", "_above64bit"}; 
    for (size_t i = 0; i < TRACE_DIFFSIZE_SUFFIXES_SIZE; ++i) {
        if (operandval_outfiles_diffsize[i].is_open()) operandval_outfiles_diffsize[i].close();
    }
    if (debugfile.is_open()) debugfile.close();
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
        return Usage();

    // open 2 trace files
    scheduler_outfile.open(KnobSchedulerOutputFile.Value().c_str(), ios_base::binary | ios_base::trunc);


    for (size_t i = 0; i < TRACE_SUFFIXES_SIZE; ++i) {
        ostringstream ldfilename;
        ldfilename << dec << KnobLoadValOutputFile.Value().c_str() << trace_suffixes[i];
        loadval_outfiles[i].open(ldfilename.str().c_str());
        loadval_outfiles[i] << "Index,PC,Source Reg/Addr,Data Value,Diff Source,Data Size" << endl;
    }
    for (size_t i = 0; i < TRACE_SUFFIXES_SIZE; ++i) {
        ostringstream opfilename;
        opfilename << dec << KnobOperandValOutputFile.Value().c_str() << trace_suffixes[i];
        operandval_outfiles[i].open(opfilename.str().c_str());
        operandval_outfiles[i] << "Index,PC,Source Reg/Addr,Data Value,Diff Source,Data Size" << endl;
    }

    if (KnobOperandValDiffDataSizeOutput.Value()){ 
        
        for (size_t i = 0; i < TRACE_DIFFSIZE_SUFFIXES_SIZE; ++i) {
            ostringstream opfilename;
            opfilename << dec << KnobOperandValOutputFile.Value().c_str() << trace_diffsize_suffixes[i];
            operandval_outfiles_diffsize[i].open(opfilename.str().c_str());
            operandval_outfiles_diffsize[i] << "Index,PC,Source Reg/Addr,Data Value,Diff Source,Data Size" << endl;
        }
    }

 
    //Debug file that writes out human-readable instructions
    if (KnobDebug.Value()) {
        debugfile.open(KnobDebugFile.Value().c_str());
    }

    // Register Routine to be called to instrument rtn
    INS_AddInstrumentFunction(Instruction, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
