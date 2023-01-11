/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

//does not work - will error out

#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;
using std::hex;
using std::dec;

ofstream OutFile;
int count = 0;

VOID PrintIns(const string s)
{
    count ++;
    if (count > 1000) return;
    OutFile << hex << "Ins: " << s << endl;
}

// IMG instrumentation routine - called once per image upon image load
VOID ImageLoad(IMG img, VOID * v) {
    // OutFile << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << endl;
    // For simplicity, instrument only the main image. This can be extended to any other image of course.
    // if (IMG_Name(img) == "/usr/lib/x86_64-linux-gnu/libatlas.so.3") {
        // OutFile << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << endl; 
        // To find all the instructions in the image, we traverse the sections of the image.
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
            // OutFile << "entering SEC\t" << SEC_Name(sec) << endl; 
            // For each section, process all RTNs.
            for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
                // OutFile << "entering RTN\t" << RTN_Name(rtn) << endl; 
                // Many RTN APIs require that the RTN be opened first.
                RTN_Open(rtn);
                // OutFile << "First Ins: " << INS_Disassemble(RTN_InsHead(rtn)) << endl;
                // output(RTN_Address(rtn), static_cast<ostream*>(v)); // Calls PIN_GetSourceLocation for the RTN address.

                // Call PIN_GetSourceLocation for all the instructions of the RTN.
                for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
                    INS_InsertCall(RTN_InsHead(rtn), 
                                IPOINT_BEFORE,
                                AFUNPTR(PrintIns),
                                IARG_PTR, 
                                new string(INS_Disassemble(ins)),
                                // new string(INS_Disassemble(RTN_InsHead(rtn))),
                                IARG_END
                                );
                    // OutFile << hex << "InsAddr: " << INS_Address(ins) << "\tIns: " << INS_Disassemble(ins) << endl;
                    // output(INS_Address(ins), static_cast<ostream*>(v), ins); // Calls PIN_GetSourceLocation for a single instruction.
                }
                // OutFile << "exiting RTN\t" << RTN_Name(rtn) << endl; 
                RTN_Close(rtn); // Don't forget to close the RTN once you're done.
            }
            // OutFile << "exiting SEC\t" << SEC_Name(sec) << endl; 
        }
    // }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "print_ins_in_image.out", "specify output file name");
VOID Fini(INT32 code, VOID* v)
{
    // fprintf(trace, "#eof\n");
    OutFile << "#eof" << endl;
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    // PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
    cerr << "Prints inst, inst addr and load value for mem loads" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());
    // INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
