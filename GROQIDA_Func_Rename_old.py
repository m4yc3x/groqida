from idaapi import plugin_t, PLUGIN_PROC, PLUGIN_KEEP, PLUGIN_SKIP, PLUGIN_OK
from ida_kernwin import ask_text, info, Form, Choose, register_action, action_handler_t, attach_action_to_menu
from ida_kernwin import WOPN_DP_TAB, BWN_DISASM
import ida_kernwin
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import json
import urllib.request
import urllib.error
import ssl
import re

print("Loading AI Function Rename plugin...")  # Debug print

PLUGIN_NAME = "AI Function Rename"
PLUGIN_HOTKEY = "Ctrl-Alt-N"
PLUGIN_COMMENT = "Use AI to suggest function names based on their behavior"
PLUGIN_HELP = "This plugin uses AI to analyze function behavior and suggest appropriate names"
PLUGIN_VERSION = "0.1"

# Replace with your actual Groq API key
groq_api_key = "YOUR_GROQ_API_KEY"
groq_model = "llama-3.1-8b-instant"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Form template
class AIFunctionRenameForm(Form):
    def __init__(self):
        # Cache all functions once
        self.function_list = self.populate_functions()
        
        Form.__init__(self, r"""STARTITEM {id:Function1}
BUTTON YES* Analyze Selected
BUTTON CANCEL Cancel
AI Function Rename

Select up to 5 functions to analyze:
<##Function 1##Function1:{Function1}>
<##Function 2##Function2:{Function2}>
<##Function 3##Function3:{Function3}>
<##Function 4##Function4:{Function4}>
<##Function 5##Function5:{Function5}>
""", {
            'Function1': Form.DropdownListControl(
                items=self.function_list,
                readonly=True,
                selval=0,
                width=60
            ),
            'Function2': Form.DropdownListControl(
                items=self.function_list,
                readonly=True,
                selval=0,
                width=60
            ),
            'Function3': Form.DropdownListControl(
                items=self.function_list,
                readonly=True,
                selval=0,
                width=60
            ),
            'Function4': Form.DropdownListControl(
                items=self.function_list,
                readonly=True,
                selval=0,
                width=60
            ),
            'Function5': Form.DropdownListControl(
                items=self.function_list,
                readonly=True,
                selval=0,
                width=60
            ),
        })
        self.Compile()

    def populate_functions(self):
        """Get all function names and addresses"""
        functions = ["<none>"]  # First option is none
        # Collect and sort functions alphabetically
        func_list = []
        for ea in Functions():
            name = ida_funcs.get_func_name(ea)
            if name:  # Only add if we got a valid name
                func_list.append(f"{name} at {hex(ea)}")
        
        # Add sorted functions to the list
        functions.extend(sorted(func_list, key=lambda x: x.split(' at ')[0].lower()))
        return functions

    def get_selected_functions(self):
        """Get list of selected functions (excluding <none> selections)"""
        selected = []
        try:
            # Get the control values using Form's built-in methods
            for i in range(1, 6):
                try:
                    # Get value using the form's internal method
                    idx = getattr(self, f'Function{i}').value
                    print(f"DEBUG: Function{i} selected index = {idx}")
                    
                    if idx is not None and idx > 0 and idx < len(self.function_list):
                        func_desc = self.function_list[idx]
                        print(f"DEBUG: Selected function: {func_desc}")
                        selected.append(func_desc)
                        
                except Exception as e:
                    print(f"DEBUG: Error getting value for Function{i}: {str(e)}")
                    continue
            
            print(f"DEBUG: Total selected functions: {len(selected)}")
            return selected
            
        except Exception as e:
            print(f"DEBUG: Error in get_selected_functions: {str(e)}")
            return []

class AIFunctionRenameActionHandler(action_handler_t):
    def __init__(self, plugin):
        action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.show_form()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class AIFunctionRename(plugin_t):
    flags = PLUGIN_PROC | PLUGIN_KEEP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    
    def __init__(self):
        plugin_t.__init__(self)

    def init(self):
        """
        This is called when IDA loads the plugin.
        """
        print("Initializing AI Function Rename plugin...")  # Debug print
        try:
            # Ensure we have the decompiler
            if not ida_hexrays.init_hexrays_plugin():
                print("Hex-rays decompiler is not available!")
                return PLUGIN_SKIP
            
            print("Plugin initialized successfully!")
            print("AI Function Rename plugin is now available in the Plugins menu")
            return PLUGIN_OK
            
        except Exception as e:
            print(f"Failed to initialize plugin: {str(e)}")
            return PLUGIN_SKIP

    def get_function_info(self, func_desc):
        """Get function decompilation and disassembly for the given function description"""
        try:
            # Extract address from "name at 0x123456" format
            addr = int(func_desc.split(" at ")[1], 16)
            print(f"DEBUG: Getting info for function at {hex(addr)}")
            
            func = ida_funcs.get_func(addr)
            if not func:
                print(f"DEBUG: Could not get function at {hex(addr)}")
                return None

            # Get decompiled code
            try:
                cfunc = ida_hexrays.decompile(func)
                if not cfunc:
                    print(f"DEBUG: Could not decompile function at {hex(addr)}")
                    return None

                # Get the pseudocode
                lines = []
                for line in cfunc.get_pseudocode():
                    lines.append(ida_lines.tag_remove(line.line))
                
                decompiled = "\n".join(lines)
                print(f"DEBUG: Successfully decompiled function at {hex(addr)}")
                return decompiled
                
            except Exception as e:
                print(f"DEBUG: Decompilation error: {str(e)}")
                return None
                
        except Exception as e:
            print(f"DEBUG: Error getting function info: {str(e)}")
            return None

    def query_groq(self, func_desc, pseudocode):
        """Query Groq API for function name suggestion"""
        try:
            print(f"DEBUG: Querying Groq for function: {func_desc}")
            
            # Create SSL context with TLS 1.2
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            prompt = f"""Given this assembly function code, suggest a clear and descriptive name that follows common programming conventions. The name should be in snake_case and describe the function's purpose concisely. Only respond with the suggested name, no explanation or label.

{pseudocode}"""

            headers = {
                "Authorization": f"Bearer {groq_api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Python/3.x"
            }
            
            data = {
                "model": groq_model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a reverse engineering assistant that analyzes decompiled C/C++ functions and suggests appropriate function names even if you're not sure what the function does. Only respond with the suggested name in snake_case format! No explanation, no label like 'suggested name:' or anything else! Only reply with the name!"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.1,
                "max_tokens": 10,
                "top_p": 1,
                "stream": False
            }

            print("DEBUG: Sending request to Groq API")
            print(f"DEBUG: Request data: {json.dumps(data, indent=2)}")
            
            request = urllib.request.Request(
                GROQ_API_URL,
                data=json.dumps(data).encode('utf-8'),
                headers=headers,
                method='POST'
            )
            
            with urllib.request.urlopen(request, context=context) as response:
                result = json.loads(response.read().decode('utf-8'))
                suggested_name = result["choices"][0]["message"]["content"].strip()
                print(f"DEBUG: Got suggestion from Groq: {suggested_name}")
                return suggested_name
                
        except urllib.error.HTTPError as e:
            print(f"DEBUG: HTTP Error {e.code}: {e.reason}")
            print(f"DEBUG: Response body: {e.read().decode('utf-8')}")
            return None
        except ssl.SSLError as e:
            print(f"DEBUG: SSL Error: {str(e)}")
            return None
        except Exception as e:
            print(f"DEBUG: Failed to query Groq API: {str(e)}")
            return None

    def sanitize_function_name(self, name):
        """Sanitize function name to only include alphanumeric and underscores"""
        # Replace any non-alphanumeric (or underscore) with underscore
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '', name).lower()
        sanitized = sanitized.replace('suggested', '').replace('name', '').replace('suggest', '')
        # Ensure it starts with a letter
        if sanitized and not sanitized[0].isalpha():
            sanitized = 'f_' + sanitized
        return sanitized

    def rename_function(self, func_desc, new_name):
        """Rename function in IDA database"""
        try:
            # Extract address from "name at 0x123456" format
            addr = int(func_desc.split(" at ")[1], 16)
            sanitized_name = self.sanitize_function_name(new_name)
            
            print(f"DEBUG: Renaming function at {hex(addr)} to {sanitized_name}")
            
            if ida_name.set_name(addr, sanitized_name):
                print(f"DEBUG: Successfully renamed function to {sanitized_name}")
                return True
            else:
                print(f"DEBUG: Failed to rename function to {sanitized_name}")
                return False
                
        except Exception as e:
            print(f"DEBUG: Error renaming function: {str(e)}")
            return False

    def show_form(self):
        """Show the form and handle user interaction"""
        print("DEBUG: show_form started")
        
        try:
            f = AIFunctionRenameForm()
            ok = f.Execute()
            print(f"DEBUG: Form.Execute() returned {ok}")
            
            if ok == 1:  # User clicked OK
                selected_funcs = f.get_selected_functions()
                print(f"DEBUG: Got {len(selected_funcs)} selected functions")
                
                if not selected_funcs:
                    info("No functions selected")
                    f.Free()
                    return

                results = []
                errors = []
                renamed = []
                for func_desc in selected_funcs:
                    try:
                        print(f"DEBUG: Processing function: {func_desc}")
                        pseudocode = self.get_function_info(func_desc)
                        if pseudocode is None:
                            print(f"DEBUG: Failed to get function info for {func_desc}")
                            errors.append(f"Failed to decompile: {func_desc}")
                            continue
                            
                        suggested_name = self.query_groq(func_desc, pseudocode)
                        if suggested_name is None:
                            print(f"DEBUG: Failed to get AI suggestion for {func_desc}")
                            errors.append(f"Failed to get AI suggestion for: {func_desc}")
                            continue
                        
                        # Store result before renaming
                        results.append(f"Original: {func_desc}\nSuggested: {suggested_name}\n")
                        
                        # Try to rename the function
                        if self.rename_function(func_desc, suggested_name):
                            renamed.append(func_desc)
                        
                        print(f"DEBUG: Successfully processed {func_desc}")
                        
                    except Exception as e:
                        print(f"DEBUG: Error processing function {func_desc}: {str(e)}")
                        errors.append(f"Error processing {func_desc}: {str(e)}")

                # Show results
                message = ""
                if results:
                    message += "Suggested Names:\n\n" + "\n".join(results)
                if renamed:
                    if message:
                        message += "\n\n"
                    message += f"Successfully renamed {len(renamed)} functions"
                if errors:
                    if message:
                        message += "\n\n"
                    message += "Errors:\n" + "\n".join(errors)
                
                if message:
                    info(message)
                else:
                    info("No results generated")

            f.Free()
                
        except Exception as e:
            print(f"DEBUG: Exception in show_form: {str(e)}")
            info(f"Error showing form: {str(e)}")

    def run(self, arg):
        """
        This is called when the user activates the plugin.
        """
        print("Plugin run() called")  # Debug print
        self.show_form()

    def term(self):
        """
        This is called when IDA unloads the plugin.
        """
        print("Plugin terminated")
        if hasattr(self, '_form'):
            try:
                self._form.Free()
            except:
                pass

def PLUGIN_ENTRY():
    """
    This is the entry point of the plugin.
    """
    print("PLUGIN_ENTRY called")  # Debug print
    return AIFunctionRename()

# Helper function to get all functions
def Functions(start=None, end=None):
    """Get all function addresses in the binary"""
    func = ida_funcs.get_next_func(start) if start else ida_funcs.get_next_func(0)
    while func and (not end or func.start_ea < end):
        yield func.start_ea
        func = ida_funcs.get_next_func(func.start_ea)

