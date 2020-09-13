# Script to detect Stack strings, and retype the dynamically loaded Windows API where possible
# @author BitsOfBinary
# @category Analysis

import ghidra.app.script.GhidraScript
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import VariableStorage
from ghidra.program.model.lang import Register
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.address import GenericAddress
from ghidra.program.model.data import CategoryPath, ArrayDataType


class StackString:
    """
    Class to represent a stack string

    Attributes:
        val (string): the string value of the stack string
        addr (Address): the local address of the stack string
        var (Variable): the variable representing the start of the stack string
    """

    def __init__(self):
        self.val = ""
        self.addr = None
        self.var = None


class DynamicAPILoadingHandler:
    """
    Class used to handle the labelling and retyping of dynamically loaded Windows APIs

    Attributes:
        windows_data_type_manager (DataTypeManager): the data type manager specifically for Windows symbols
        category_path (CategoryPath): the path to the Windows APIs
    """

    def __init__(self, windows_data_type_manager, category_path=CategoryPath("/winbase.h/functions")):
        self.windows_data_type_manager = windows_data_type_manager
        self.category_path = category_path

    def global_variable_handler(self, dyn_loaded_addr, stack_str):
        """
        Handler to rename + retype global variables

        Args:
            dyn_loaded_addr (Address): the address of the global variable
            stack_str (StackString): the stack string to use in the renaming/retyping
        """

        print("Renaming global variable %s as %s" % (str(dyn_loaded_addr), stack_str.val))
        createLabel(dyn_loaded_addr, stack_str.val, True)

        try:
            dyn_data_type = self.windows_data_type_manager.getDataType(
                self.category_path, stack_str.val
            )

            if dyn_data_type:
                print("Retyping global variable %s as %s" % (str(dyn_loaded_addr), stack_str.val))
                createData(dyn_loaded_addr, dyn_data_type)

        except CodeUnitInsertionException:
            print("Could not retype: %s" % (stack_str.val))

    def local_variable_handler(self, local_variable, stack_str):
        """
        Handler to rename + retype local variables

        Args:
            local_variable (Variable): the local variable to retype/rename
            stack_str (StackString): the stack string to use in the renaming/retyping
        """

        print("Renaming local variable %s as %s" % (local_variable.getName(), stack_str.val))
        local_variable.setName(stack_str.val, SourceType.USER_DEFINED)

        try:
            dyn_data_type = self.windows_data_type_manager.getDataType(
                self.category_path, stack_str.val
            )

            if dyn_data_type:
                print("Retyping local variable %s as %s" % (local_variable.getName(), stack_str.val))
                local_variable.setDataType(dyn_data_type, SourceType.USER_DEFINED)

        except CodeUnitInsertionException:
            print("Could not retype: %s" % (stack_str.val))


class StackStringFunctionHandler:
    """
    Class used to handle the parsing of stack strings per function,
    and then passing these to DynamicAPILoadingHandler

    Attributes:
        MAX_STEPS (int): max number of instructions to go through in a function
        MIN_STACK_STRING_LENGTH (int): min length to parse out a stack string
        STACK_REGISTERS (list): registers that are used to reference the stack
        RETURN_REGISTERS (list): registers that usually contain return values

        dyn_api_handler (DynamicAPILoadingHandler): the handler for renaming/retyping the APIs
        current_func (Function): the current function for the handler
        end_of_func_addr (Address): the end of the current function
        stack_strs (list): StackStrings that have been parsed out
        building_stack_str (StackString): temporary StackString for while it is being parsed
        ins (Instruction): the current instruction in the function
        counter (int): the number of instructions iterated through in the current function
        previous_stack_offset (long): the previous stack offset to make sure the stack string is being properly constructed
    """

    MAX_STEPS = 1000
    MIN_STACK_STRING_LENGTH = 2
    STACK_REGISTERS = ["ESP", "EBP", "RSP", "RBP"]
    RETURN_REGISTERS = ["EAX", "RAX"]

    def __init__(self, dyn_api_handler, current_func, end_of_func_addr):
        self.dyn_api_handler = dyn_api_handler
        self.current_func = current_func
        self.end_of_func_addr = end_of_func_addr

        self.current_func.setCustomVariableStorage(True)

        self.stack_strs = []
        self.building_stack_str = StackString()
        self.ins = None
        self.counter = 0
        self.previous_stack_offset = None

    def find_local_variable(self, addr):
        """
        Find the local variable at the provided address

        Args:
            addr (Address): the address to check if there is a local variable at
        """
        for local_variable in self.current_func.getLocalVariables():
            if local_variable.getMinAddress() == addr:
                return local_variable
                
    def init_building_stack_str(self):
        """
        Initialise a building stack string
        """

        self.building_stack_str.addr = self.ins.getOperandReferences(0)[0].getToAddress()

        for variable in self.current_func.getLocalVariables():

            if variable.getStackOffset() == self.building_stack_str.addr.getOffset():
                self.building_stack_str.var = variable

    def stack_char_handler(self, stack_char, stack_offset):
        """
        Handler to deal with parsed characters being placed on the stack

        Args:
            stack_char (char): a single char parsed from off the stack
            stack_offset (int): the offset onto the stack to prevent random character being added to the StackString
        """
        # Check the scalar is in a "nice" ASCII range
        if stack_char >= 0x2E and stack_char <= 0x7A:
                
            # If we're building a StackString, make sure we've only incremented one byte on the stack
            if self.previous_stack_offset and (stack_offset - self.previous_stack_offset) == 1:
            
                self.building_stack_str.val += chr(stack_char)
                self.previous_stack_offset = stack_offset
                
            # Otherwise, start building a new StackString, and save off the stack offset
            else:
                self.building_stack_str = StackString()
                self.init_building_stack_str()
                
                self.building_stack_str.val += chr(stack_char)
                self.previous_stack_offset = stack_offset

        # If the scalar is NULL, then it is likely the end of the string
        elif stack_char == 0 and len(self.building_stack_str.val) >= self.MIN_STACK_STRING_LENGTH:

            print("\nStack string found:")
            print("Value: %s" % (self.building_stack_str.val))
            print("Address: %s" % (str(self.building_stack_str.addr)))
            print("Variable: %s\n" % (str(self.building_stack_str.var)))

            # Rename the stack string variable
            self.building_stack_str.var.setName(self.building_stack_str.val + "_stack_str", SourceType.USER_DEFINED)

            # Get the data type for "char"
            single_char_data_type = getDataTypes("char")[0]

            # Create a proper length character array DataType
            data_type = ArrayDataType(single_char_data_type, len(self.building_stack_str.val) + 1, 1)

            # Setup the VariableStorage associated with the character array
            stack_offset = self.building_stack_str.var.getStackOffset()
            variable_storage = VariableStorage(
                self.current_func.getProgram(),
                stack_offset,
                len(self.building_stack_str.val) + 1,
            )

            # Set the new data type
            self.building_stack_str.var.setDataType(data_type, variable_storage, True, SourceType.USER_DEFINED)

            # Add to the stack strings, and clear the building stack string
            self.stack_strs.append(self.building_stack_str)
            self.building_stack_str = StackString()
            self.previous_stack_offset = None

    def call_handler(self, stack_adjustment):
        """
        Handler for instructions that are calls that could be used in retyping

        Args:
            stack_adjustment (int): the amount to adjust the stack offset when referencing local variables
        """

        call_addr = self.ins.getOpObjects(0)[0]

        if type(call_addr) == GenericAddress:
            symbol = getSymbolAt(call_addr).getName()

            if "GetProcAddress" in symbol or "LoadLibrary" in symbol:

                backwards_counter = 0
                backwards_ins = self.ins

                while backwards_counter < 5:
                    backwards_ins = backwards_ins.getPrevious()

                    # Only check for potential references to loading values off register offsets (i.e. stack)
                    if (
                        backwards_ins.getMnemonicString() == "LEA"
                        and type(backwards_ins.getOpObjects(1)[0]) == Register
                    ):

                        for stack_str in self.stack_strs:
                            loaded_var_offset_scalar = backwards_ins.getOpObjects(1)[1].subtract(stack_adjustment)

                            if loaded_var_offset_scalar.getSignedValue() == stack_str.var.getStackOffset():
                                forward_ins = self.ins.getNext()

                                if forward_ins.getMnemonicString() == "MOV":
                                    dyn_loaded_addr = forward_ins.getOperandReferences(0)[0].getToAddress()

                                    # Case for global variables
                                    if dyn_loaded_addr.isMemoryAddress():
                                        self.dyn_api_handler.global_variable_handler(dyn_loaded_addr, stack_str)

                                    # Case for local variables
                                    else:
                                        local_variable = self.find_local_variable(dyn_loaded_addr)

                                        if local_variable:
                                            self.dyn_api_handler.local_variable_handler(local_variable, stack_str)

                                    return

                    backwards_counter += 1

    def instruction_iterator(self):
        """
        Handler to iterate over the instructions in the current function
        """

        self.ins = getFirstInstruction(self.current_func)

        # Set a stack adjustment variable
        # BP stacks are off by 0x4, and SP stacks are off by a variable amount
        if self.ins.getMnemonicString() == "SUB" and self.ins.getOpObjects(0)[0].getName() in ["ESP", "RSP"]:
            stack_adjustment = self.ins.getOpObjects(1)[0].getUnsignedValue()

        else:
            stack_adjustment = 0x4

        # Check that the instruction exists first to prevent errors being thrown
        while (
            self.ins
            and self.ins.getAddress() < self.end_of_func_addr
            and self.counter != self.MAX_STEPS
        ):

            # Case: potential stack string loading OR loading EAX into another address
            if self.ins.getMnemonicString() == "MOV":

                # This is safe to do as MOV always has two operands
                op1 = self.ins.getOpObjects(0)
                op2 = self.ins.getOpObjects(1)

                # Case: If a scalar is being moved into a register offset
                if type(op1[0]) == Register and type(op2[0]) == Scalar:

                    if op1[0].getName() in self.STACK_REGISTERS and len(op1) > 1 and type(op1[1]) == Scalar:

                        stack_char = op2[0].getUnsignedValue()
                        stack_offset = op1[1].getSignedValue()
                        self.stack_char_handler(stack_char, stack_offset)
                        
                # TODO: case where a register value is being moved onto the stack
                # This could be if a single character is stored in a register, and moved onto the stack that way instead of as a literal

            elif self.ins.getMnemonicString() == "CALL":
                self.call_handler(stack_adjustment)

            self.ins = self.ins.getNext()
            self.counter += 1


class StackStringProgramHandler:
    """
    Class to handle the script

    Attributes:
        MAX_FUNCTIONS (int): maximum functions to check

        category_path (CategoryPath): the path to the Windows API functions
        data_type_managers (list): all loaded data type managers
        windows_data_type_manager (DataTypeManager): the Windows specific data type manager
        dyn_api_handler (DynamicAPILoadingHandler): the handler to retype/rename the APIs
    """

    MAX_FUNCTIONS = 10000

    def __init__(self, category_path):
        self.category_path = category_path

        self.data_type_managers = None
        self.windows_data_type_manager = None
        self.dyn_api_handler = None

    def get_data_type_managers(self):
        """
        Method to get all data type managers
        """

        tool = state.getTool()
        service = tool.getService(DataTypeManagerService)
        self.data_type_managers = service.getDataTypeManagers()

    def get_windows_data_type_manager(self):
        """
        Method to load the Windows specific data type manager
        """

        for data_type_manager in self.data_type_managers:
            if "windows" in data_type_manager.getName():
                self.windows_data_type_manager = data_type_manager
                break

    def run_function_handler(self, function):
        """
        Method to run the StackStringFunctionHandler on a specified function

        Args:
            function (Function): the function to parse stack strings in
        """

        end_of_func_addr = function.getBody().getMaxAddress()

        func_handler = StackStringFunctionHandler(
            self.dyn_api_handler, function, end_of_func_addr
        )

        func_handler.instruction_iterator()

    def run(self, choice_code):
        """
        Method to run the function handler on either a specified function, or all functions

        Args:
            choice_code (int): 0 if running on current function, 1 if running on all functions
        """

        self.get_data_type_managers()
        self.get_windows_data_type_manager()

        self.dyn_api_handler = DynamicAPILoadingHandler(self.windows_data_type_manager, self.category_path)

        if choice_code == 0:
            current_func = getFunctionContaining(currentAddress)
            self.run_function_handler(current_func)

        elif choice_code == 1:
            func = getFirstFunction()
            func_counter = 0

            while func and func_counter < self.MAX_FUNCTIONS:
                self.run_function_handler(func)
                func = getFunctionAfter(func)

                func_counter += 1


def main():
    """
    Entry point to the script
    """

    # Define the category path to load Windows functions
    category_path = CategoryPath("/winbase.h/functions")

    program_handler = StackStringProgramHandler(category_path)

    valid_choices = ["Current function", "All functions"]
    valid_choices_mapping = {"Current function": 0, "All functions": 1}

    choice = askChoice(
        "Stack String option",
        "Do you want to run the script on the current function, or all functions?",
        valid_choices,
        None,
    )

    program_handler.run(valid_choices_mapping[choice])


if __name__ == "__main__":
    main()
