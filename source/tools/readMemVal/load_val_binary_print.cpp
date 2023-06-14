/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//
// This tool counts the number of times a routine is executed and
// the number of instructions executed in a routine
//

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include "pin.H"
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ofstream;
using std::setw;
using std::string;

ofstream OutFile;
bool going = false;

// // Holds instruction count for a single procedure
// typedef struct RtnCount
// {
//     string _name;
//     string _image;
//     string _sec;
//     ADDRINT _address;
//     RTN _rtn;
//     UINT64 _rtnCount;
//     UINT64 _icount;
//     struct RtnCount* _next;
// } RTN_COUNT;

// // Linked list of instruction counts for each routine
// RTN_COUNT* RtnList = 0;

VOID docount_rtn(const string rtn_name_to_parse_str, const string rtn_name, ADDRINT rtn_addr) { 
    if (rtn_name_to_parse_str == rtn_name){
        going = true;
    }
    if (going){
        // (*counter)++; 
        OutFile << "RTN START addr: " << hex << rtn_addr << "\t" << rtn_name << endl;
    }
}

VOID rtn_after(const string rtn_name_to_parse_str, const string rtn_name, ADDRINT rtn_addr) {
    if (going){
        OutFile << "RTN FINISH addr: " << hex << rtn_addr << "\t" << rtn_name << endl;
    }
    if (rtn_name_to_parse_str == rtn_name){
        going = false;
    }
}

// // This function is called before every instruction is executed
// VOID docount_ins(UINT64* counter, const string ins, ADDRINT ins_addr) {
//     if (going){
//         (*counter)++;
//         OutFile << "\tIns addr: " << hex << ins_addr << "\t" << ins << endl;
//     } 
    
// }

VOID ReadContent(ADDRINT ins_addr, VOID* memread_addr, UINT32 memread_size, const string ins)
{
    if (going) {
        UINT64 value = 0;
        PIN_SafeCopy(&value, memread_addr, memread_size);
        // OutFile << hex << "\tIns addr: " << ins_addr << "\t" << ins << "\tMemAddr: " << memread_addr << "\t Size: " << memread_size << "\tValue:" << (unsigned long long) value << endl;
        std::bitset<64>value_bin(value);
        OutFile << value_bin <<endl;
        // OutFile << hex <<value <<endl;
    }
    
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID* rtn_name_to_parse)
{

    KNOB< string >* rtn_name_to_parse_ptr = (KNOB< string >*)rtn_name_to_parse;
    string rtn_name_to_parse_str = rtn_name_to_parse_ptr->Value().c_str();
    // if (RTN_Name(rtn).find(".text") != std::string::npos){
    // if ((rtn_name_to_parse_str == "") || (RTN_Name(rtn) == rtn_name_to_parse_str)){ 
        RTN_Open(rtn);

        // Insert a call at the entry point of a routine to increment the call count
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount_rtn, 
        IARG_PTR, new string(rtn_name_to_parse_str),
        IARG_PTR, new string(RTN_Name(rtn)),
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rtn_after, 
        IARG_PTR, new string(rtn_name_to_parse_str),
        IARG_PTR, new string(RTN_Name(rtn)),
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_END);

        // For each instruction of the routine
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
        {
            // Insert a call to docount to increment the instruction counter for this rtn
            if (INS_IsMemoryRead(ins)){
                //std::string instrString = INS_Disassemble(ins); 
                //fprintf("%s: ", instrString.c_str());
                INS_InsertCall(ins,
                            IPOINT_BEFORE,
                            AFUNPTR(ReadContent),
                            IARG_INST_PTR,
                            IARG_MEMORYREAD_EA,
                            IARG_MEMORYREAD_SIZE, 
                            //IARG_REG_VALUE,
                            IARG_PTR, 
                            new string(INS_Disassemble(ins)),
                            IARG_END);
            } 
            // else {
            //     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount_ins, 
            //     IARG_PTR, &(rc->_icount), 
            //     IARG_PTR, new string(INS_Disassemble(ins)),
            //     IARG_INST_PTR,
            //     IARG_END);
            // }
            
        }

        RTN_Close(rtn);
    // }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "load_val_binary_print.out", "specify output file name");
KNOB< string > rtn_name_to_parse(KNOB_MODE_WRITEONCE, "pintool", "rtn_name_to_parse", "", "Specify RTN name to parse; if none, will parse all RTNs");

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID* v)
{
    // OutFile << setw(23) << "Procedure"
    //         << " " << setw(15) << "Image"
    //         << " " << setw(15) << "Sec"
    //         << " " << setw(18) << "Address"
    //         << " " << setw(12) << "Calls"
    //         << " " << setw(12) << "Instructions" << endl;

    // for (RTN_COUNT* rc = RtnList; rc; rc = rc->_next)
    // {
    //     if (rc->_icount > 0)
    //         OutFile << setw(23) << rc->_name << " " << setw(15) << rc->_image << " " << setw(15) << rc->_sec << " " << setw(18) << hex << rc->_address << dec
    //                 << " " << setw(12) << rc->_rtnCount << " " << setw(12) << rc->_icount << endl;
    // }
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
    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, &rtn_name_to_parse);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
