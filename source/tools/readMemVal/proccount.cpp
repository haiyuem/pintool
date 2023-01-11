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

ofstream outFile;

static UINT64 _tabInsCount[0x1000];
static string _tabStr[0x1000];
static UINT64 _tabInsAddr[0x1000];
static UINT64 _firstInsAddr;

// // Holds instruction count for a single procedure
// typedef struct RtnCount
// {
//     string _name;
//     string _image;
//     ADDRINT _address;
//     RTN _rtn;
//     UINT64 _rtnCount;
//     UINT64 _icount;
//     struct RtnCount* _next;
// } RTN_COUNT;

// // Linked list of instruction counts for each routine
// RTN_COUNT* RtnList = 0;

// This function is called before every instruction is executed
VOID docount(const string insDis, VOID* memaddr, UINT64 ip, const string op, VOID* rtnaddr, THREADID threadid) { 
    unsigned long long offset = (unsigned long long)ip - (unsigned long long)rtnaddr;
    _tabInsCount[offset] += 1;
    _tabStr[offset] = insDis;
    _tabInsAddr[offset] = ip;
    // (*counter)++;
    if (_firstInsAddr == 0) {
        _firstInsAddr = ip;
    }
    if (ip == _firstInsAddr){
        ADDRINT value;
        PIN_SafeCopy(&value, memaddr, sizeof(ADDRINT));
        outFile << hex << "InsAddr: " << ip << "\tCount: " << _tabInsCount[offset] << "\tLoadAddr: " << memaddr << "\tValue:" << value << "\tThread: " << threadid << endl;    
    }
    
}

// const char* StripPath(const char* path)
// {
//     const char* file = strrchr(path, '/');
//     if (file)
//         return file + 1;
//     else
//         return path;
// }

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID* v)
{
    if (RTN_Name(rtn).find("ATL_spNBmm_b1") != std::string::npos){
        // // Allocate a counter for this routine
        // RTN_COUNT* rc = new RTN_COUNT;

        // // The RTN goes away when the image is unloaded, so save it now
        // // because we need it in the fini
        // rc->_name     = RTN_Name(rtn);
        // rc->_image    = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
        // rc->_address  = RTN_Address(rtn);
        // rc->_icount   = 0;
        // rc->_rtnCount = 0;

        // // Add to list of routines
        // rc->_next = RtnList;
        // RtnList   = rc;

        RTN_Open(rtn);
        outFile << "RTN base addr: 0x" << RTN_Address(rtn) << "\t" << RTN_Name(rtn) << endl;

        // Insert a call at the entry point of a routine to increment the call count
        // RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);

        // For each instruction of the routine
        // for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
        // {
        //     // if (INS_IsMemoryRead(ins) && ((INS_Mnemonic(ins)=="MOVAPS") or (INS_Mnemonic(ins)=="MULPS"))){
        //     if (INS_IsMemoryRead(ins) && ((INS_Mnemonic(ins)=="MULPS"))){
        //         // Insert a call to docount to increment the instruction counter for this rtn
        //         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, 
        //         IARG_PTR, 
        //         new string(INS_Disassemble(ins)),
        //         IARG_MEMORYREAD_EA,
        //         IARG_ADDRINT, INS_Address(ins),
        //         IARG_PTR,
        //         new string(INS_Mnemonic(ins)),
        //         IARG_ADDRINT,
        //         RTN_Address(rtn),
        //         IARG_THREAD_ID,
        //         IARG_END);
        //     }
            
        // }

        RTN_Close(rtn);
    }

}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID* v)
{
    // outFile << setw(23) << "Procedure"
    //         << " " << setw(15) << "Image"
    //         << " " << setw(18) << "Address"
    //         << " " << setw(12) << "Calls"
    //         << " " << setw(12) << "Instructions" << endl;

    // for (RTN_COUNT* rc = RtnList; rc; rc = rc->_next)
    // {
    //     if (rc->_icount > 0)
    //         outFile << setw(23) << rc->_name << " " << setw(15) << rc->_image << " " << setw(18) << hex << rc->_address << dec
    //                 << " " << setw(12) << rc->_rtnCount << " " << setw(12) << rc->_icount << endl;
    // }
    outFile << "Addr\t\tOffset\tNumber\tDisass" << endl;
    for (UINT32 i = 0; i < 1000; i++){
        if (_tabInsCount[i])
        outFile << hex << _tabInsAddr[i] << "\t" << i << "\t" << dec << _tabInsCount[i] << "\t" << _tabStr[i] << endl;
    }
    outFile << "#eof" << endl;
    if (outFile.is_open())
    {
        outFile.close();
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

    outFile.open("proccount.out");

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
