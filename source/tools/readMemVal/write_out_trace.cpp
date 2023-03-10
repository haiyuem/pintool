/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// Write out CVP friendly binary trace. Could also be configured to print out insn details as required by CVP traces (1-1 map in human-readable format)
// Intel x86-64 instructions are "fused", e.g. one insn does both MEM and ALU. Because simulator only takes non-fused insns, we separated the fused insns into two with the same PC 
// 
//
// Trace Format :
// Inst PC 				- 8 bytes
// Next Inst PC 	- 8 bytes (next insn or branch tar)
// Inst Type			- 1 byte
// If load/storeInst
//   Effective Address 		- 8 bytes
//   Access Size (one reg)		- 1 byte
//   If load: 
//      Mem Val   - 8 bytes
// If branch
//   Taken 				- 1 byte
// Num Input Regs 			- 1 byte
// Input Reg Names 			- 1 byte each
// Num Output Regs 			- 1 byte
// Output Reg Names			- 1 byte each

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include "pin.H"
#include <list>
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ofstream;
using std::setw;
using std::string;
using std::map;

typedef std::list<REG> RegList;

ofstream OutFile;
ofstream ByteFile;
bool write_out_trace = true;
bool print = false;
bool print_ins = false;

/* maps ins opcode to ins type
  aluInstClass = 0,
  loadInstClass = 1,
  storeInstClass = 2,
  condBranchInstClass = 3,
  uncondDirectBranchInstClass = 4,
  uncondIndirectBranchInstClass = 5,
  fpInstClass = 6,
  slowAluInstClass = 7,
  undefInstClass = 8 

All instructions used in ATL_spNBmm_b1: count_unique_ins.out.in_atlaskernel
Opcode enum: extras/xed-intel64/include/xed/xed-iclass-enum.h
Category enum: xed-category-enum.h
Find opcode definition in: Intel® 64 and IA-32 Architectures Software Developer's Manual
Volume 2 (2A, 2B, 2C & 2D): Instruction Set Reference, A-Z */

char op_type_map (
INT32 Category,
BOOL IsDirectControlFlow,
OPCODE opcode,
const string ins_str
){ 
    if ((OPCODE_StringShort(opcode).find("MUL") != std::string::npos) || (OPCODE_StringShort(opcode).find("PS") != std::string::npos))
        return 0x7;
    else return 0x0;
}

// Num Input Regs 			- 1 byte
// Input Reg Names 			- 1 byte each
// Num Output Regs 			- 1 byte
// Output Reg Names			- 1 byte each
// Output Reg Values ----NO LONGER NEEDED!
//   If INT (0 to 31) or FLAG (64) 	- 8 bytes each
//   If SIMD (32 to 63)		- 16 bytes each
void Ins_InReg1(REG reg1){
    char reg_num = 0x1;
    if (write_out_trace) {
        ByteFile.write(&reg_num, 1);
        ByteFile.write((char*)(&reg1), 1);
    }
    if (print) OutFile << "\tin_reg1 " << reg1 << "(" << REG_StringShort(reg1) << ")" << endl;
}
void Ins_InReg2(REG reg1, REG reg2){
    char reg_num = 0x2;
    if (write_out_trace) {
        ByteFile.write(&reg_num, 1);
        ByteFile.write((char*)(&reg1), 1);
        ByteFile.write((char*)(&reg2), 1);
    }
    if (print) OutFile << "\tin_reg1 " << reg1 << "(" << REG_StringShort(reg1) << ")" << " in_reg2 " << reg2 << "(" << REG_StringShort(reg2) << ")" << endl;
}
void Ins_InReg3(REG reg1, REG reg2, REG reg3){
    char reg_num = 0x3;
    if (write_out_trace) {
        ByteFile.write(&reg_num, 1);
        ByteFile.write((char*)(&reg1), 1);
        ByteFile.write((char*)(&reg2), 1);
        ByteFile.write((char*)(&reg3), 1);
    }
    if (print) OutFile << "\tin_reg1 " << reg1 << "(" << REG_StringShort(reg1) << ")" << " in_reg2 " << reg2 << "(" << REG_StringShort(reg2) << ")" << " in_reg3 " << reg3 << "(" << REG_StringShort(reg3) << ")" << endl;
}

AFUNPTR InRegFuns[] = {AFUNPTR(Ins_InReg1), AFUNPTR(Ins_InReg2), AFUNPTR(Ins_InReg3)};

void Ins_OutReg1(REG reg1){
    char reg_num = 0x1;
    if (write_out_trace) {
        ByteFile.write(&reg_num, 1);
        ByteFile.write((char*)(&reg1), 1);
    }
    if (print) OutFile << "\tout_reg1 " << reg1 << "(" << REG_StringShort(reg1) << ")" << endl;
}
void Ins_OutReg2(REG reg1, REG reg2){
    char reg_num = 0x2;
    if (write_out_trace) {
        ByteFile.write(&reg_num, 1);
        ByteFile.write((char*)(&reg1), 1);
        ByteFile.write((char*)(&reg2), 1);
    }
    if (print) OutFile << "\tout_reg1 " << reg1 << "(" << REG_StringShort(reg1) << ")" << " out_reg2 " << reg2 << "(" << REG_StringShort(reg2) << ")" << endl;
}
void Ins_OutReg3(REG reg1, REG reg2, REG reg3){
    char reg_num = 0x3;
    if (write_out_trace) {
        ByteFile.write(&reg_num, 1);
        ByteFile.write((char*)(&reg1), 1);
        ByteFile.write((char*)(&reg2), 1);
        ByteFile.write((char*)(&reg3), 1);
    }
    if (print) OutFile << "\tout_reg1 " << reg1 << "(" << REG_StringShort(reg1) << ")" << " out_reg2 " << reg2 << "(" << REG_StringShort(reg2) << ")" << " out_reg3 " << reg3 << "(" << REG_StringShort(reg3) << ")" << endl;
}
AFUNPTR OutRegFuns[] = {AFUNPTR(Ins_OutReg1), AFUNPTR(Ins_OutReg2), AFUNPTR(Ins_OutReg3)};

void NoRegWriteZero(){
    char reg_num = 0x0;
    if (write_out_trace) ByteFile.write(&reg_num, 1);
}

VOID Ins_MemRead(const string ins_str, 
ADDRINT ins_addr,
ADDRINT ins_addr_next,
ADDRINT memread_addr,
UINT32 memread_size
){
    if (print_ins) OutFile << ins_str << endl;
    if (print) OutFile << hex << "MemRead: PC: " << ins_addr << " " << ins_str << endl;
    if (write_out_trace) ByteFile.write((char*)(&ins_addr), 8);
    if (print) OutFile << hex << "\t next PC: " << ins_addr_next << endl;
    if (write_out_trace) ByteFile.write((char*)(&ins_addr_next), 8);
    // If load/storeInst
    //   Effective Address 			- 8 bytes
    //   Access Size (one reg)		- 1 byte
    char inst_type = 0x1;
    if (write_out_trace) {
        ByteFile.write(&inst_type, 1);
        ByteFile.write((char*)&memread_addr, 8);
        ByteFile.write((char*)&memread_size, 1);
    }
    UINT64 value = 0;
    size_t read_size = PIN_SafeCopy((VOID*)(&value), (VOID*)memread_addr, memread_size);
    assert(read_size == (size_t)memread_size);

    if (write_out_trace) ByteFile.write((char*)&value, 8);
    if (print) OutFile << "\tInsType: 1, memread_addr:  " << memread_addr << " memread_size: " << memread_size << " val: " << value << endl;
}

VOID Ins_MemWrite(const string ins_str, 
ADDRINT ins_addr,
ADDRINT ins_addr_next,
ADDRINT memwrite_addr,
UINT32 memwrite_size
){
    if (print_ins) OutFile << ins_str << endl;
    if (print) OutFile << hex << "MemWrite: PC: " << ins_addr << " " << ins_str << endl;
    if (write_out_trace) ByteFile.write((char*)(&ins_addr), 8);
    if (print) OutFile << hex << "\t next PC: " << ins_addr_next << endl;
    if (write_out_trace) ByteFile.write((char*)(&ins_addr_next), 8);
    char inst_type = 0x2;
    if (write_out_trace) {
        ByteFile.write(&inst_type, 1);
        ByteFile.write((char*)&memwrite_addr, 8);
        ByteFile.write((char*)&memwrite_size, 1);
    }
    if (print) OutFile << "\tInsType: 2, memwrite_addr:  " << memwrite_addr << " memwrite_size: " << memwrite_size << endl;   
}

VOID Ins_Branch(const string ins_str, 
ADDRINT ins_addr,
ADDRINT ins_addr_next,
INT32 Category,
BOOL IsDirectControlFlow,
BOOL branch_taken,
ADDRINT branch_target_addr
){
    if (print_ins) OutFile << ins_str << endl;
    if (print) OutFile << hex << "Branch: PC: " << ins_addr << " " << ins_str << endl;

    //Second round for non-MEM, excluding prefetch because they are just MEM 
    // Inst PC 				- 8 bytes
    if (write_out_trace) ByteFile.write((char*)(&ins_addr), 8);
    ADDRINT ins_addr_next_br = branch_taken ? branch_target_addr : ins_addr_next;
    // Inst PC Next				- 8 bytes
    if (print) OutFile << hex << "\t next PC: " << ins_addr_next_br << endl;
    if (write_out_trace) ByteFile.write((char*)(&ins_addr_next_br), 8);
    // Inst Type			- 1 byte
    char inst_type = 0x8; // invalid
    if (Category == XED_CATEGORY_COND_BR) inst_type = 0x3;
    // else if ((Category == XED_CATEGORY_UNCOND_BR) || (Category == XED_CATEGORY_RET)){
    else {
        if (IsDirectControlFlow) inst_type = 0x4;
        else inst_type = 0x5;
    }
    if (inst_type == 0x8){
        OutFile << "Ins type Error!!!! Ins: " << ins_str << " " << CATEGORY_StringShort(Category) << endl;
        exit(-1);
    }
    if (write_out_trace) ByteFile.write(&inst_type, 1);
    // If branch
    //   Taken 				- 1 byte
    if (write_out_trace) ByteFile.write((char*)(&branch_taken), 1);
    if (print) OutFile << "\tInsType: " << (int)inst_type << " Branch Taken: " << branch_taken << endl;
    // if (branch_taken){
    //     ByteFile.write((char*)(&branch_target_addr), 8);
    //     OutFile << "\tTarget: " << branch_target_addr << endl;
    // }
}

VOID Ins_Nonmem(const string ins_str, 
OPCODE opcode, 
VOID* ins_addr,
VOID* ins_addr_next,
INT32 Category,
BOOL IsDirectControlFlow
){
    //Second round for non-MEM, excluding prefetch because they are just MEM 
    if (print_ins) OutFile << ins_str << endl;
    if ((opcode != XED_ICLASS_PREFETCHT0) && (opcode != XED_ICLASS_PREFETCHT1)){
        // Inst PC 				- 8 bytes
        if (print) OutFile << hex << "NonMem: PC: " << ins_addr << " " << ins_str << endl;
        if (write_out_trace) ByteFile.write((char*)(&ins_addr), 8);
        if (print) OutFile << hex << "\t next PC: " << ins_addr_next << endl;
        if (write_out_trace) ByteFile.write((char*)(&ins_addr_next), 8);
        // Inst Type			- 1 byte
        char inst_type = op_type_map (Category, IsDirectControlFlow, opcode, ins_str);
        if (write_out_trace) ByteFile.write(&inst_type, 1);
        if (print) OutFile << "\tInst_type: " << (int)inst_type << " opcode:" << opcode << endl;            
    }
    // char* buffer = new char[1];
    // buffer[0] = 0x1;
}

void insert_call_regs(int num_regs_in, int num_regs_out, INS ins, IARGLIST regs_in, IARGLIST regs_out){
    if (num_regs_in != 0) {
        INS_InsertCall(ins, 
        IPOINT_BEFORE,
        AFUNPTR(InRegFuns[num_regs_in-1]),
        IARG_IARGLIST, regs_in,
        IARG_END
        );
    }else {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(NoRegWriteZero), IARG_END);
    }
    if (num_regs_out != 0) {
        INS_InsertCall(ins, 
        IPOINT_BEFORE,
        AFUNPTR(OutRegFuns[num_regs_out-1]),
        IARG_IARGLIST, regs_out,
        IARG_END
        );
    } else {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(NoRegWriteZero), IARG_END);
    }
}

// Pin calls this function every time a new rtn is executed
// separate fused insns (LD/ST + ALU) into two with the same PC 
// First check if it's a LD/ST, then proceed normally as non-mem inst
VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{
    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    // Here are different types of matches: exact match, matching substring RTN/IMG
    // if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){
    if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn).find(rtn_name_to_parse_str) != std::string::npos)){
    // if ((rtn_name_to_parse_str == "") || (IMG_Name(SEC_Img(RTN_Sec(rtn))).find(rtn_name_to_parse_str) != std::string::npos)){
        RTN_Open(rtn);
        // OutFile << hex << "RTN base addr: 0x" << RTN_Address(rtn) << "\t" << RTN_Name(rtn) << endl;
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)){
            //Figure out In/Out regs
            int num_regs_in = 0;
            int num_regs_out = 0;
            IARGLIST regs_in = IARGLIST_Alloc();
            IARGLIST regs_out = IARGLIST_Alloc();
            for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); i++){
                REG regr = INS_RegR(ins, i);
                if ((regr != REG_INVALID()) && !(REG_is_any_flags_type(regr))){
                    IARGLIST_AddArguments(regs_in, 
                    IARG_PTR, REG_FullRegName(regr),
                    IARG_END);
                    num_regs_in++;
                }
            }
            for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); i++){
                REG regw = INS_RegW(ins, i);
                if ((regw != REG_INVALID()) && !(REG_is_any_flags_type(regw))){
                    IARGLIST_AddArguments(regs_out, 
                    IARG_PTR, REG_FullRegName(regw),
                    IARG_END);
                    num_regs_out++;
                }
            }

            if (INS_IsMemoryRead(ins)){
                INS_InsertCall(ins, 
                IPOINT_BEFORE,
                AFUNPTR(Ins_MemRead),
                IARG_PTR, new string(INS_Disassemble(ins)), //ins string
                IARG_INST_PTR, //ins addr
                IARG_ADDRINT, INS_NextAddress(ins), //next ins addr
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_END
                );
                insert_call_regs(num_regs_in, num_regs_out, ins, regs_in, regs_out);
            }
            
            if (INS_IsMemoryWrite(ins)){
                INS_InsertCall(ins, 
                IPOINT_BEFORE,
                AFUNPTR(Ins_MemWrite),
                IARG_PTR, new string(INS_Disassemble(ins)), //ins string
                IARG_INST_PTR, //ins addr
                IARG_ADDRINT, INS_NextAddress(ins), //next ins addr
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_END
                );
                insert_call_regs(num_regs_in, num_regs_out, ins, regs_in, regs_out);
            }

            //branch or call
            //xbegin/xend is a control op but doesn't have a br target. exclude it for now
            if (INS_IsControlFlow(ins) && ((INS_Opcode(ins) != XED_ICLASS_XBEGIN) && (INS_Opcode(ins) != XED_ICLASS_XEND))){
                INS_InsertCall(ins, 
                IPOINT_BEFORE,
                AFUNPTR(Ins_Branch),
                IARG_PTR, new string(INS_Disassemble(ins)), //ins string
                IARG_INST_PTR, //ins addr
                IARG_ADDRINT, INS_NextAddress(ins), //next ins addr
                IARG_PTR, INS_Category(ins),
                IARG_PTR, INS_IsDirectControlFlow(ins), //branch or call
                IARG_BRANCH_TAKEN,
                IARG_BRANCH_TARGET_ADDR,
                IARG_END
                );
            } else {
                //ALU 
                INS_InsertCall(ins, 
                IPOINT_BEFORE,
                AFUNPTR(Ins_Nonmem),
                IARG_PTR, new string(INS_Disassemble(ins)), //ins string
                IARG_PTR, INS_Opcode(ins), 
                IARG_INST_PTR, //ins addr
                IARG_ADDRINT, INS_NextAddress(ins), //next ins addr
                IARG_PTR, INS_Category(ins),
                IARG_PTR, INS_IsDirectControlFlow(ins), //branch or call
                IARG_END
                );
            }
            if (!INS_IsPrefetch(ins)) {
                //New change 2022/10/19: if the first insn generated is a load, then the second insn will have the load's output reg as its input reg to show dependency. It no longer needs the original input reg because the potential waiting will be performed by the load. The output reg stays the same. 
                if (INS_IsMemoryRead(ins)) insert_call_regs(num_regs_out, num_regs_out, ins, regs_out, regs_out);
                else insert_call_regs(num_regs_in, num_regs_out, ins, regs_in, regs_out);
            }

            IARGLIST_Free(regs_in);
        }
        RTN_Close(rtn);
    }

}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "write_out_trace.out", "specify output file name");
KNOB< string > KnobTraceFile(KNOB_MODE_WRITEONCE, "pintool", "trace", "trace", "specify trace name");
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID* v)
{
    // OutFile << "#eof" << endl;
    if (OutFile.is_open())
    {
        OutFile.close();
    }
    if (ByteFile.is_open())
    {
        ByteFile.close();
    }
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This Pintool counts the number of times a routine is executed" << endl;
    cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // OutFile.open("write_out_trace.out");
    // ByteFile.open("trace");
    OutFile.open(KnobOutputFile.Value().c_str());
    ByteFile.open(KnobTraceFile.Value().c_str());
    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
