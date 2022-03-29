import idc
import ida_ua
import idaapi
import ida_hexrays
import idautils
import ida_kernwin
import sys
import collections
       
icon = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x002\x00\x00\x002\x08\x06\x00\x00\x00\x1e?\x88\xb1\x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00\x00\x04gAMA\x00\x00\xb1\x8f\x0b\xfca\x05\x00\x00\x00\tpHYs\x00\x00\x0e\xc3\x00\x00\x0e\xc3\x01\xc7o\xa8d\x00\x00\x03\x80IDAThC\xed\x9aY\xa8MQ\x18\xc7\xaf)"\xb3d&E(E\n\xa1P\xca\x90\x07\xca\x8b\xe1ARW(\n%\xc3\x83\x07O\x8a<\xc8\x93!\x0f<IJ\x19R\xa6\x92\xc8\x10\x19\xca\x98)\xa1\xcc\x91\xf9\xf7\xbfgo}w\xb5\xcf={\x9f\xb3\xf6\xba\xf7\xe8\xfe\xea\xd7\xda\xa7\xee]\xdfYk\xed5}\xf7\xd64\xd3\xc4h\x11\x95\xe52\x14\xa7\xe1p\x1c\x83}\xb1\x1d\xfe\xc6\xcfx\x03_\xe0Y<\x8a\x7f\xb0\xc9\xd0\x05W\xe3u\xd4\x17\xcb\xe2\x11\x9c\x87\x8dJ[\\\x86\xcf1\xe9KfQ\x9d0\x01\x83\xa3W\xe7\x02&}\xa9J\xdc\x86^H3Gf\xe0!\xd4+\x95\x84F\xe84>\xc4[\xf8\t5z=q\x10\x8e\xc3\x99X\x0c\xcd\xa3\xa9\xf8\xbe\xeeSN,\xc5w\xe8\xf6\xe4O<\x83\x9a\xe8\xc5\x1a\xe8\xb2\x02\x9f\xa0[\x97|\x80\x031\x17\xe6\xe3Gt\x83\x9eG\xadP\xe5\xb2\n\xdd:\xe5K\xec\x8e^\x19\x82I#\xb1\x1b\xd3\x8e@C\x0c\xc3\xbb\xe8\xd6\xafN\xf2FgT\x85n\x90\xed\xd8\x06}\xa1\x0e\xb9\x88n\x1c-\xed^X\x8bn\xe5;\xb15\xfaF\x8d\xd1"ac}E-\x12\x15\xd1\t\xdf\xa0\xad\xf8\x0ej\x94\xf2b<\xdaxr\x1fV\x84\x86\xd5\xadt"\xe6\x8d\xe6\x9e\x8d\xa9U\xb1\xa2Q9\x87\xb6B\x1d)B\xa0W\xec\x07\xda\xd8e\xcf\x95Qh+\x92\xda\'B\xb1\x17ml\xbd\xd2e\xa1s\x94\xad\xe8\x1e\xb6\xc2PLF\x1b\xff\x1b\xea4\x9d\x8a\x96Q)\xc6Fe\xcc\x15\xfcUx\x0c\x82\x8e*:\xfa\xc7\xe8\x983\xb2\xf0X\x1a\xdb\x10m\x82\x16U\x1c\x92\x0fx\xbb\xf0\xf8\x0fm\x9c\xa9\xb0\r\xe9\x17\x951:\x0c\x86F\xaf\xb3\xa5[T\x96\xc46D7;\xcb\xdb\xa8\x0c\xc9\x97\xa8\x8c\xe9\x1a\x95%\xb1\r\xb1\xcf\xc2\xfd\x1c\x02\xcd\x0b\x8b&}*\xec\x97\xd5=\xc2\xd2?*C\xd2!*ct\\I\x85m\xc8\xfd\xa8\x8c\xf1~\xa4N\x81{=\xd0\t9\x15\xb6!\xeeD\x9b\x14\x95\xa1\xe8\x8d\xee\xca\xf9,*31\x07\xed\x86\xa4\xfbH\x9e\x87E\x97\xc5h\xe3\xeb\xea\xdb\x1e3\xa3\xf3\x8e\xadH.\xc1P\x1cG\x1b\xfb\x18\x96\xcdA\xb4\x95\xe9\x8e\x1d\x02\x9d\xb0m\\\xa9\x11*\x9b\xe9\xe8V\xa8;v\xde(\x91ac*;\xe9.\xc5\x99\xd1\xa4\xb7\x95j\x93\x1a\x81y\xb1\tm<\xb9\x19+f4\xba\x15?B\x1fI\x07\x97\xb9\xe8&9\xb4\rx\x8b\xb5\x07m\xe5R\x07:]\x85}\xa1t\x93\xdb\x88\xef\xa8d\x9d7\xb4\xc3^F\x1bD*Q\xe0\x1e\xf7\xb3\xa2%u=&\xa5\x9bN\xa1w4\xbc7\xd1\r&w`G\xcc\xca\x14L\xea \xab2\x92\xdeQ\x1a\xf3)&\x05\x94jP\xa9\xac\xba:d\x01^E%\x15\x92\xeaq]\x87\x99H\x93\xc4V\xcfk\x7f\x99]\xf7\xa98\'\xf1\x15\xc6\x07\xbd\x01\xd8\x07\x07c\xb1\xb9\xa5\x9f=\x8c\x8b\xea>\xd5g%\xee*<\xfae\x0b&\xf5^\xb9>\xc6Y(\x92\xd2P2\x97\xd7L(\xd7\xe4f;\xb2\xfa\x1a\xd7\xa0{\x8e\xdb\x88I?\x9f[cD\x0fT/^\xc3\xa4\xe0\xaeZ\xa1N`-6\xb4Gl\xc0\xa4\xdf/9g*\xfdc\xa8Pb[\xf3\xa7\x17\xea2\xa69\xa5\xe0J&\xe8\xde\xafUJ\xafQ\xda?\xe4\xa81[\x0b\x8f\xf5\xc8m\xce\xe4I\xf09\x93\'\x8d2g\xf2Bs\xe3\xbfiL\xb1\x05\xa0*\x1bSl\xce,\xc4\xaa#\xe95\xd3?\x1eT%nc\x0e`\xd5\xb2\x1c/\xe1~l\x8c\xdc[3)\xa8\xa9\xf9\x0bt\x9f\xacg\xfa\xc9\xf21\x00\x00\x00\x00IEND\xaeB`\x82'

class condstanta_form_t(ida_kernwin.Form):

    def __init__(self,hexrays):
        self.hexrays = hexrays
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:searchStr}
BUTTON YES* Search
BUTTON CANCEL Cancel
Condstanta

{FormChangeCb}
<#Exact number - 1, 0x1, 1.1 or -1<br>Range (Colon separated)<br>List (Comma separated)<br>Empty value to match all for condition search#Search for:{searchStr}>

<##What to search for##Search for constants used in conditions:{rCond}>
<Find set of constants in single function:{rFunc}>{cType}>
<##Requires a number, minimum is 2.#Minimal number of matching constants:{numOfMatched}>
<##Use Hexrays?##Yes:{rHexYes}>
<No:{rHexNo}>{cHexrays}>    

""", {
            'searchStr': F.StringInput(),
            'cHexrays': F.RadGroupControl(( "rHexYes", "rHexNo")),
            'cType': F.RadGroupControl(("rCond", "rFunc")),
            'numOfMatched': F.NumericInput(value=2, tp=F.FT_UINT64),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self, fid):
        if fid == -1:
            self.EnableField(self.cHexrays, self.hexrays)
        if fid == -1 or fid == self.cType.id:
            if self.GetControlValue(self.cType) == 0:
                self.EnableField(self.numOfMatched, False)
            else:
                self.EnableField(self.numOfMatched, True)
        return 1

# CTree visitor for finding constants
class custom_ctree_visitor(ida_hexrays.ctree_visitor_t):
    def __init__(self,decompiled_function,uniques):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST) 
        self.decompiled_function = decompiled_function
        self.lvars = self.decompiled_function.get_lvars()
        self.uniques = uniques
    
    def visit_insn(self, i):
        if i.op == ida_hexrays.cit_switch:
            for case in list(i.to_specific_type.cswitch.cases):
                for case_value in case.values:
                    self.uniques.add((case.ea,case_value))
        return 0
   
    def visit_expr(self, e):     
        if e.op == ida_hexrays.cot_num: # This gets the value of a number
            if e.ea == idaapi.BADADDR:
                self.uniques.add((self.decompiled_function.entry_ea,e.n._value))
            else:
                self.uniques.add((e.ea,e.n._value))
        if e.op == ida_hexrays.cot_fnum:
            if e.ea == idaapi.BADADDR:
                self.uniques.add((self.decompiled_function.entry_ea,e.fpc.fnum.float))
            else:
                self.uniques.add((e.ea,e.fpc.fnum.float))
        return 0

class Condstanta(idaapi.action_handler_t):
    result_window_title = "Condstanta Results"
    result_window_columns_names = ["Address","Function","Type","Decimal","Hex","Comment"]
    result_window_columns_sizes = [10,15,5,10,10,30]
    result_window_columns = [ list(column) for column in zip(result_window_columns_names,result_window_columns_sizes)]
    result_window_row = collections.namedtuple("CondstantaResultRow",result_window_columns_names)

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.window_counter = 0
        self.hexrays = False
        self.functions_list = []
        self.from_value = -sys.maxsize
        self.to_value = 2 * sys.maxsize + 1
        self.const_list = []
        self.input_type = 0 # Input type is: 0 - range, 1 - list

    def activate(self, ctx):
        # Check if hexrays can even be used
        if not ida_hexrays.init_hexrays_plugin():
            self.hexrays = False
        else:
            self.hexrays = True
        
        # Show the form
        f = condstanta_form_t(self.hexrays)
        # Compile (in order to populate the controls)
        f.Compile()
        f.searchStr.value = ""
        if self.hexrays:
            f.cHexrays.value = 0
        else:
            f.cHexrays.value = 1
        # Execute the form
        ok = f.Execute()
        # If the form was confirmed
        if ok == 1:
            search_value = f.searchStr.value
            ok = self.parse_input(f.searchStr.value) # Parse value
            if f.cHexrays.value == 0: # Yes - 0, No - 1; Need to negate
                self.hexrays = True
            else:
                self.hexrays = False 
            search_type = f.cType.value
            self.num_of_matched = f.numOfMatched.value
            if search_type and self.num_of_matched < 2: # Make sure that at least 2 constants must match
                ida_kernwin.warning("Number of common constants must be 2 or higher.")
                return
        # Dispose the form
        f.Free()
        if ok:
            ida_kernwin.show_wait_box("Condstanta is running ... ")
            rows = []
            # We likley have a valid query, fill the functions list
            self.functions_list = []
            for segment in idautils.Segments():
                self.functions_list.extend(list(idautils.Functions(idc.get_segm_start(segment),idc.get_segm_end(segment))))
            # Based on search_type run correct function
            if search_type == 0:
                # Search for constatns in condtions 
                rows = self.find_cond()
            else:
                # Search for multiple consts in a function
                if (self.input_type and len(self.const_list) > 1) or (self.input_type == 0 and self.from_value < self.to_value and search_value != ""): # Input type must be list or range
                    rows = self.find_const_func()
                else:
                    ida_kernwin.warning("Selected search type requires the input to be a list with at least two elements (for example: \"100,200\") or range of values.")
                    ida_kernwin.hide_wait_box() 
                    return
            results_window = CondstantaEmbeddedChooser(f"{self.result_window_title}-{self.window_counter}",self.result_window_columns,rows,idaapi.load_custom_icon(data=icon, format="png"))
            results_window.Show()
            self.window_counter += 1
            hooks.set_chooser(results_window)
            ida_kernwin.hide_wait_box() 

    def get_func_name_pretty(self,ea):
        demangled_name = idc.demangle_name(idc.get_func_name(ea),idc.get_inf_attr(idc.INF_SHORT_DN))
        if demangled_name:
            demangled_name = demangled_name[:demangled_name.find("(")]
            found_in_name = demangled_name
        else:
            found_in_name = idc.get_func_name(ea)
        return found_in_name
        

    def parse_input(self,search_str):
        # Reset all to defaults
        self.from_value = -sys.maxsize
        self.to_value = 2 * sys.maxsize + 1
        self.const_list = []
        if not search_str: # Empty, search all
            # Empty search string means serch all, default values for from/to/input_type
            self.input_type = 0

        elif "," in search_str: # List
            self.input_type = 1 # Input type is list
            for item in search_str.split(","):
                try:
                    if "x" in item: # hex
                        self.const_list.append(int(item,16))
                    elif "." in item: # float
                        self.const_list.append(float(item))
                    else: # int
                        self.const_list.append(int(item))
                except:
                    ida_kernwin.warning("Error parsing the number value!")
                    return 0

        elif ":" in search_str: # Range
            self.input_type = 0 # Input type range
            try: # Parse self.from_value
                self.from_value = search_str[:search_str.find(":")]
                if "x" in self.from_value:
                    self.from_value = int(self.from_value,16)
                elif "." in self.from_value:
                    self.from_value = float(self.from_value)
                else:
                    self.from_value = int(self.from_value)
            except:
                ida_kernwin.warning("Error parsing the 'from' value!")
                return 0
            try: # Parse self.to_value
                self.to_value  = search_str[search_str.find(":")+1:]
                if "x" in self.to_value:
                    self.to_value = int(self.to_value,16)
                elif "." in self.to_value:
                    self.to_value = float(self.to_value)
                else:
                    self.to_value = int(self.to_value)
            except:
                ida_kernwin.warning("Error parsing the 'to' value!")
                return 0
            if self.to_value < self.from_value:
                # To value higher then from
                ida_kernwin.warning("The 'from' value is higher than the 'to' value!")
                return 0

        else: # Single number
            self.input_type = 0
            try:
                if "x" in search_str:
                    self.from_value = int(search_str,16)
                elif "." in search_str:
                    self.from_value = float(search_str)
                else:
                    self.from_value = int(search_str)
                self.to_value = self.from_value
            except:
                ida_kernwin.warning("Error parsing the number value!")
                return 0
        
        return 1

    def find_const_func(self):
        if self.hexrays:
            return self.find_const_func_hexrays()
        else:
            return self.find_const_func_disass()
    

    def find_const_func_hexrays(self):
        results = []
        for function_ea in self.functions_list:
            if ida_kernwin.user_cancelled():
                ida_kernwin.hide_wait_box()  
                return results
            uniques = set() # used to collect results and avoid duplicits
            unique_values = set() # used to count unique matched values
            tmp_results = []
            try:
                decompiled_function = idaapi.decompile(function_ea)
                if decompiled_function:
                    # Use a simple visitor to fill the set with ea and values
                    custom_visitor = custom_ctree_visitor(decompiled_function,uniques)
                    custom_visitor.apply_to(decompiled_function.body, None)
                    if len(uniques) >= 2: # More than one item found
                        for item in uniques:
                            # First find if we have matching constants
                            value = item[1]
                            address = item[0]
                            # If the value is int create the negative one through XOR
                            if isinstance(value,int):
                                negative_value = -((value ^ 0xffffffffffffffff) + 1)
                            else:
                                # In case of float this is ok
                                negative_value = value
                            if address == idaapi.BADADDR:
                                address = function_ea
                            # If positive value matches
                            if ((self.input_type == 1 and value in self.const_list)
                            or (self.input_type == 0 and (value >= self.from_value and value <= self.to_value))):
                                unique_values.add(value)
                                try:
                                    # Float values do not convert to hex
                                    hex_val = hex(value)
                                except TypeError:
                                    hex_val = ""
                                tmp_results.append(list(Condstanta.result_window_row(hex(address),self.get_func_name_pretty(function_ea),"",str(value),hex_val,"")))
                            # If negative value matches
                            elif ((self.input_type == 1 and negative_value in self.const_list)
                            or (self.input_type == 0 and (negative_value >= self.from_value and negative_value <= self.to_value))):
                                unique_values.add(negative_value)
                                try:
                                    # Float values do not convert to hex
                                    hex_val = hex(negative_value)
                                except TypeError:
                                    hex_val = ""
                                tmp_results.append(list(Condstanta.result_window_row(hex(address),self.get_func_name_pretty(function_ea),"",str(negative_value),hex_val,"")))
                        if len(unique_values) >= self.num_of_matched: # Two or more constants matched in current function
                            results.extend(tmp_results) # Add tmp_results to final
                                    
            except ida_hexrays.DecompilationFailure:
                pass
        return results

    def get_negative_disass(self,op):
        # Get negative value based on the size of the operand
        if op.dtype == 0x0: # Byte
            return -(((op.value & 0xff) ^ 0xff) + 1)
        elif op.dtype == 0x1: # Word
            return -(((op.value & 0xffff) ^ 0xffff) + 1)
        elif op.dtype == 0x2: # Dword
            return -(((op.value & 0xffffffff) ^ 0xffffffff) + 1)
        elif op.dtype == 0x7: # Qword
            return -((op.value ^ 0xffffffffffffffff) + 1)

    def find_const_func_disass(self):
        results = []
        for function_ea in self.functions_list:
            if ida_kernwin.user_cancelled():
                ida_kernwin.hide_wait_box()  
                return results
            current_function = idaapi.get_func(function_ea)
            uniques = set() # used to collect results and avoid duplicits
            unique_values = set() # used to count unique matched values
            for inst_ea in idautils.Heads(current_function.start_ea,current_function.end_ea):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn,inst_ea) != idaapi.BADADDR:
                    for op in insn.ops:
                        # Handle switc-case values
                        switch_info = idaapi.get_switch_info(inst_ea)
                        if switch_info:
                            cases = idaapi.calc_switch_cases(inst_ea,switch_info)
                            for case_index in range(0,cases.cases.size()):
                                # Get the value
                                for value in cases.cases[case_index]:
                                    if (cases.targets[case_index],value) not in uniques:
                                        if ((self.input_type == 1 and value in self.const_list)
                                        or (self.input_type == 0 and (value >= self.from_value and value <= self.to_value))):
                                            uniques.add((cases.targets[case_index],value))
                                            unique_values.add(value)                                           
                        # Look for immediate values in other instructions
                        if op.type == 0x5:
                            # op.value holds immediate value
                            negative_value = self.get_negative_disass(op)
                            if (insn.ea,op.value) not in uniques:
                                if ((self.input_type == 1 and op.value in self.const_list)
                                or (self.input_type == 0 and (op.value >= self.from_value and op.value <= self.to_value))):
                                    uniques.add((insn.ea,op.value))
                                    unique_values.add(op.value)
                                elif ((self.input_type == 1 and negative_value in self.const_list)
                                or (self.input_type == 0 and (negative_value >= self.from_value and negative_value <= self.to_value))):
                                    uniques.add((insn.ea,negative_value))
                                    unique_values.add(negative_value)
            if len(unique_values) >= self.num_of_matched: # More than 2 unique values identified
                for item in uniques:
                    # item[0] is EA, item[1] is value
                    comment = self.get_comment_disass(item[0])
                    try:
                        # Float values do not convert to hex
                        hex_val = hex(item[1])
                    except TypeError:
                        hex_val = ""
                    results.append(list(Condstanta.result_window_row(hex(item[0]),self.get_func_name_pretty(function_ea),"",str(item[1]),hex_val,comment)))
        return results

    def find_cond(self):
        if self.hexrays:
            return self.find_cond_hexrays()
        else:
            return self.find_cond_disass()

    def find_cond_hexrays(self):
        results = []
        for function_ea in self.functions_list:
            try:
                decompiled_function = ida_hexrays.decompile(function_ea)
            except:
                continue
            if decompiled_function:
                # Workaround to populate IDA treeitems
                code = decompiled_function.pseudocode
                for item in decompiled_function.treeitems:
                    if item.op == ida_hexrays.cit_if:
                        comment = self.get_comment_hexrays(item.ea,idaapi.ITP_BRACE2,decompiled_function)
                        # Simple IF (argc > 2)
                        if (item.to_specific_type.cif.expr.op >= 22 and item.to_specific_type.cif.expr.op <= 31):# or item.to_specific_type.cif.expr.op == ida_hexrays.cot_lnot:
                            # Handle all comparisons
                            # In this case look at right side of comparison for a constant value 
                            if item.to_specific_type.cif.expr.y and (item.to_specific_type.cif.expr.y.n or item.to_specific_type.cif.expr.y.fpc): # Check if there is a Y operand and if it is a number, if it is, get its value
                                if item.to_specific_type.cif.expr.y.n: # int
                                    value = item.to_specific_type.cif.expr.y.n._value
                                    negative_value = -((value ^ 0xffffffffffffffff) + 1)
                                else: # float
                                    value = item.to_specific_type.cif.expr.y.fpc.fnum.float
                                    negative_value = value
                                if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                or self.input_type == 1 and value in self.const_list): # If the value is in range, add to result table
                                    try:
                                        # Float values do not convert to hex
                                        hex_val = hex(value)
                                    except TypeError:
                                        hex_val = ""
                                    results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"IF",str(value),hex_val,comment)))
                                elif ((self.input_type == 0 and (negative_value >= self.from_value and negative_value <= self.to_value))
                                or self.input_type == 1 and negative_value in self.const_list): # if the input type is list and the value is one of those we are looking fro add it
                                    try:
                                        # Float values do not convert to hex
                                        hex_val = hex(negative_value)
                                    except TypeError:
                                        hex_val = ""
                                    results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"IF",str(negative_value),hex_val,comment)))
                        elif item.to_specific_type.cif.expr.op == ida_hexrays.cot_lor or item.to_specific_type.cif.expr.op == ida_hexrays.cot_land:
                            # Condition with LOR/LAND, go through all sub-conditions and check constants
                            expr_list = [item.to_specific_type.cif.expr.x,item.to_specific_type.cif.expr.y]
                            while expr_list:
                                current_expr = expr_list.pop(0)
                                if (current_expr.op >= 22 and current_expr.op <= 31):
                                    # All comparisons
                                    if current_expr.y and (current_expr.y.n or current_expr.y.fpc): # Check if there is a Y operand and if it is a number, if it is, get its value
                                        if current_expr.y.n: # int
                                            value = current_expr.y.n._value
                                            negative_value = -((value ^ 0xffffffffffffffff) + 1)
                                        else: # float
                                            value = current_expr.y.fpc.fnum.float
                                            negative_value = value
                                        
                                        if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                        or self.input_type == 1 and value in self.const_list): # If the value is in range, add to result table
                                            try:
                                                # Float values do not convert to hex
                                                hex_val = hex(value)
                                            except TypeError:
                                                hex_val = ""
                                            results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"IF",str(value),hex_val,comment)))
                                        elif ((self.input_type == 0 and (negative_value >= self.from_value and negative_value <= self.to_value))
                                        or self.input_type == 1 and negative_value in self.const_list):
                                            try:
                                                # Float values do not convert to hex
                                                hex_val = hex(negative_value)
                                            except TypeError:
                                                hex_val = ""
                                            results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"IF",str(negative_value),hex_val,comment)))
                                elif current_expr.op == ida_hexrays.cot_lor or current_expr.op == ida_hexrays.cot_land:
                                    # Another LAND/LOR
                                    expr_list.extend([current_expr.x,current_expr.y])
                                elif not current_expr.y:
                                    # Something else
                                    value = 0
                                    if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                    or self.input_type == 1 and value in self.const_list): # If the value is in range, add to result table
                                        results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"IF",str(value),hex(value),comment)))
                        elif not item.to_specific_type.cif.expr.y:
                            # if none of the above matches it can be assumed that if(function_call()) or similiar is the case if there is no Y operand and thus we compare to 0
                            value = 0
                            if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                            or self.input_type == 1 and value in self.const_list): # If the value is in range, add to result table
                                results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"IF",str(value),hex(value),comment)))   
                    elif item.op == ida_hexrays.cit_switch:
                        for case in list(item.to_specific_type.cswitch.cases):
                            for case_value in case.values:
                                negative_value = -((case_value ^ 0xffffffffffffffff) + 1)
                                #comment = self.get_comment_hexrays(case.ea,idaapi.ITP_CASE,decompiled_function)
                                tl = idaapi.treeloc_t()
                                tl.ea = case.ea
                                tl.itp = idaapi.ITP_CASE # comments for case
                                comment = decompiled_function.get_user_cmt(tl,1)
                                if not comment:
                                    comment = ""
                                if ((self.input_type == 0 and (case_value >= self.from_value and case_value <= self.to_value))
                                or self.input_type == 1 and case_value in self.const_list):
                                    # case comments dont work
                                    results.append(list(Condstanta.result_window_row(hex(case.ea),self.get_func_name_pretty(function_ea),"CASE",str(case_value),hex(case_value),comment)))
                                elif ((self.input_type == 0 and (negative_value >= self.from_value and negative_value <= self.to_value))
                                or self.input_type == 1 and negative_value in self.const_list):
                                    results.append(list(Condstanta.result_window_row(hex(case.ea),self.get_func_name_pretty(function_ea),"CASE",str(negative_value),hex(negative_value),comment)))
                    elif item.op == ida_hexrays.cit_while:
                        comment = self.get_comment_hexrays(item.ea,idaapi.ITP_BRACE2,decompiled_function)
                        # Simple IF (argc > 2)
                        if (item.to_specific_type.cwhile.expr.op >= 22 and item.to_specific_type.cwhile.expr.op <= 31):# or item.to_specific_type.cif.expr.op == ida_hexrays.cot_lnot:
                            # Handle all comparisons
                            # In this case look at right side of comparison for a constant value 
                            if item.to_specific_type.cwhile.expr.y and (item.to_specific_type.cwhile.expr.y.n or item.to_specific_type.cwhile.expr.y.fpc): # Check if there is a Y operand and if it is a number, if it is, get its value
                                if item.to_specific_type.cwhile.expr.y.n: # int
                                    value = item.to_specific_type.cwhile.expr.y.n._value
                                    negative_value = -((value ^ 0xffffffffffffffff) + 1)
                                else: # float
                                    value = item.to_specific_type.cwhile.expr.y.fpc.fnum.float
                                    negative_value = value
                                
                                if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                or self.input_type == 1 and value in self.const_list): # If the value is in range, add to result table
                                    try:
                                        # Float values do not convert to hex
                                        hex_val = hex(value)
                                    except TypeError:
                                        hex_val = ""
                                    results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"LOOP",str(value),hex_val,comment)))
                                elif ((self.input_type == 0 and (negative_value >= self.from_value and negative_value <= self.to_value))
                                or self.input_type == 1 and negative_value in self.const_list):
                                    try:
                                        # Float values do not convert to hex
                                        hex_val = hex(negative_value)
                                    except TypeError:
                                        hex_val = ""
                                    results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"LOOP",str(negative_value),hex_val,comment)))
                        elif item.to_specific_type.cwhile.expr.op == ida_hexrays.cot_lor or item.to_specific_type.cwhile.expr.op == ida_hexrays.cot_land:
                            # Condition with LOR/LAND, go through all sub-conditions and check constants
                            expr_list = [item.to_specific_type.cwhile.expr.x,item.to_specific_type.cwhile.expr.y]
                            while expr_list:
                                current_expr = expr_list.pop(0)
                                if (current_expr.op >= 22 and current_expr.op <= 31):
                                    # All comparisons
                                    if current_expr.y and (current_expr.y.n or current_expr.y.fpc): # Check if there is a Y operand and if it is a number, if it is, get its value
                                        if current_expr.y.n: # int
                                            value = current_expr.y.n._value
                                            negative_value = -((value ^ 0xffffffffffffffff) + 1)
                                        else: # float
                                            value = current_expr.y.fpc.fnum.float
                                            negative_value = value
                                        if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                        or self.input_type == 1 and value in self.const_list): # If the value is in range, add to result table
                                            try:
                                                # Float values do not convert to hex
                                                hex_val = hex(value)
                                            except TypeError:
                                                hex_val = ""
                                            results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"LOOP",str(value),hex_val,comment)))
                                        elif ((self.input_type == 0 and (negative_value >= self.from_value and negative_value <= self.to_value))
                                        or self.input_type == 1 and negative_value in self.const_list):
                                            try:
                                                # Float values do not convert to hex
                                                hex_val = hex(negative_value)
                                            except TypeError:
                                                hex_val = ""
                                            results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"LOOP",str(negative_value),hex_val,comment)))
                                elif current_expr.op == ida_hexrays.cot_lor or current_expr.op == ida_hexrays.cot_land:
                                    # Another LAND/LOR
                                    expr_list.extend([current_expr.x,current_expr.y])
                                elif not current_expr.y:
                                    # Something else
                                    value = 0
                                    if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                    or self.input_type == 1 and value in self.const_list): # If the value is in range, add to result table
                                        results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"LOOP",str(value),hex(value),comment)))
                        elif not item.to_specific_type.cwhile.expr.y:
                            # if none of the above matches it can be assumed that while(function_call()) or while(1) is the case
                            if not item.to_specific_type.cwhile.expr.x:
                                value = 1
                                if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                or self.input_type == 1 and value in self.const_list): # If the value is in range, add to result table
                                    results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"LOOP (ENDLESS)",str(value),hex(value),comment)))
                            else:
                                value = 0
                                if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                or self.input_type == 1 and value in self.const_list): # If the value is in range, add to result table
                                    results.append(list(Condstanta.result_window_row(hex(item.ea),self.get_func_name_pretty(function_ea),"LOOP",str(value),hex(value),comment)))
        return results

    def find_cond_disass(self):
        results = []
        for function_ea in self.functions_list:
            current_function = idaapi.get_func(function_ea)
            for block in idaapi.FlowChart(current_function):
                #print(f"EA: {block.start_ea}, SUC: {len(list(block.succs()))}")
                succs_count = len(list(block.succs()))
                if succs_count == 2:
                    # If statement
                    inst_list = list(idautils.Heads(block.start_ea,block.end_ea))[::-1]
                    if inst_list:
                        # Sets the amount of instructions which will be checked for presence of a constant
                        instruction_limit = 4
                        counter = 0
                        found = False
                        # Starts from the end of the block and goes up
                        for inst_ea in inst_list:
                            insn = ida_ua.insn_t()
                            if ida_ua.decode_insn(insn,inst_ea) != idaapi.BADADDR:
                                if insn.get_canon_feature() & 0xffff == 0x300 or insn.get_canon_feature() & 0xffff == 0x604:
                                    # Instruction does not modify any operands and uses first and second (most common test/cmp instructions)
                                    # OR The instruction is using second and third operant (SLTI in MIPS for example)
                                    for op in insn.ops:
                                        # Look for immediate values
                                        if op.type == 0x5:
                                            negative_value = self.get_negative_disass(op)
                                            # Get comments
                                            comment = self.get_comment_disass(insn.ea)
                                            if not comment:
                                                comment = self.get_comment_disass(inst_list[0])
                                            # op.value holds immediate value
                                            if ((self.input_type == 0 and (op.value >= self.from_value and op.value <= self.to_value))
                                            or self.input_type == 1 and op.value in self.const_list):
                                                results.append(list(Condstanta.result_window_row(hex(insn.ea),self.get_func_name_pretty(function_ea),"IF",str(op.value),hex(op.value),comment)))
                                            elif ((self.input_type == 0 and (negative_value >= self.from_value and negative_value <= self.to_value))
                                            or self.input_type == 1 and negative_value in self.const_list): 
                                                results.append(list(Condstanta.result_window_row(hex(insn.ea),self.get_func_name_pretty(function_ea),"IF",str(negative_value),hex(negative_value),comment)))
                                            found = True

                                    if not found:
                                        # Likely a correct instruction but not comparing to any constant value, assuming checking a return value of a function
                                        value = 0
                                        found = True
                                        # Get comments
                                        comment = self.get_comment_disass(insn.ea)
                                        if not comment:
                                            comment = self.get_comment_disass(inst_list[0])
                                        if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                        or self.input_type == 1 and value in self.const_list):
                                            results.append(list(Condstanta.result_window_row(hex(insn.ea),self.get_func_name_pretty(function_ea),"IF",str(value),hex(value),comment)))
                                            
                            if counter == instruction_limit: # IF we reached instruction limit and found some suspicious instruction
                                # We got too far
                                break
                            counter += 1
                            
                elif succs_count > 2:
                    # switch
                    for insn_ea in idautils.Heads(block.start_ea,block.end_ea):
                        switch_info = idaapi.get_switch_info(insn_ea)
                        if switch_info:
                            cases = idaapi.calc_switch_cases(insn_ea,switch_info)
                            for case_index in range(0,cases.cases.size()):
                                # Get the value
                                for value in cases.cases[case_index]:
                                    # Comments are taken from cases targets
                                    comment = self.get_comment_disass(cases.targets[case_index])
                                    if ((self.input_type == 0 and (value >= self.from_value and value <= self.to_value))
                                    or self.input_type == 1 and value in self.const_list):
                                        results.append(list(Condstanta.result_window_row(hex(cases.targets[case_index]),self.get_func_name_pretty(function_ea),"CASE",str(value),hex(value),comment)))
        return results

    def get_comment_disass(self,ea):
        comment = idaapi.get_cmt(ea,0) # non-repeatable
        if not comment:
            comment = idaapi.get_cmt(ea,1) # repeatable
            if not comment:
                # There are not comments
                comment = ""
        return comment

    def get_comment_hexrays(self,ea,type,decompiled_function):
        tl = idaapi.treeloc_t()
        tl.ea = ea
        tl.itp = type 
        comment = decompiled_function.get_user_cmt(tl,1)
        if not comment:
            comment = ""
        return comment


    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
class CondstantaEmbeddedChooser(ida_kernwin.Choose):
    def __init__(self,title,columns,items,icon,embedded=False):
        ida_kernwin.Choose.__init__(self,title,columns,embedded=embedded,width=100)
        self.items = items
        self.icon = icon

    def Refresh(self):
        for item in self.items:
            demangled_name = idc.demangle_name(idc.get_func_name(int(item[0],16)),idc.get_inf_attr(idc.INF_SHORT_DN))
            if demangled_name:
                demangled_name = demangled_name[:demangled_name.find("(")]
                found_in_name = demangled_name
            else:
                found_in_name = idc.get_func_name(int(item[0],16))
            item[1] = found_in_name
        ida_kernwin.Choose.Refresh(self)
    
    def OnClose(self):
        # Remove self from refresh list
        hooks.del_chooser(self)

    def GetItems(self):
        return self.items

    def SetItems(self,items):
        if items is None:
            self.items = []
        else:
            self.items = items
        self.Refresh()

    def OnCommand(self,number,cmd_id):
        pass

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self,number):
        row = Condstanta.result_window_row(*self.items[number])
        destination = row.Address
        ida_kernwin.jumpto(int(destination,16))

    def OnGetLine(self,number):
        return self.items[number]



class condstanta_plugin_t(idaapi.plugin_t):
    comment = "Condstanta"
    help = "Condstanta plugin allows you to search for various uses of constants."
    wanted_name = "Condstanta"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        export_desc = idaapi.action_desc_t(
            'condstanta:plugin',   # The action name. This acts like an ID and must be unique
            'Condstanta',  # The action text.
            Condstanta(),   # The action handler.
            '',      # Optional: the action shortcut
            'Plugin for searching for constants in binaries.',  # Optional: the action tooltip (available in menus/toolbar)
            idaapi.load_custom_icon(data=icon, format="png"))           # Optional: the action icon (shows when in menus/toolbars)
        idaapi.register_action(export_desc)
        idaapi.attach_action_to_menu("Search", "condstanta:plugin", idaapi.SETMENU_APP)

    def run(self):
        pass

    def term(self):
        pass

class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        self.choosers = []
        idaapi.UI_Hooks.__init__(self)
    
    def current_widget_changed(self, widget, prev_widget):
        title = ida_kernwin.get_widget_title(widget)
        if title and "Condstanta" in title and self.choosers:
            for chooser in self.choosers:
                if chooser:
                    chooser.Refresh()
    
    def set_chooser(self,chooser):
        # Add new chooser for refresh
        self.choosers.append(chooser)

    def del_chooser(self,chooser):
        # Remove closed choosers
        self.choosers.remove(chooser)

# Run the hooks
hooks = Hooks()
hooks.hook()


def PLUGIN_ENTRY():
    return condstanta_plugin_t()