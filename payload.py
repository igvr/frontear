import json
import socket
import sys
import traceback
import inspect
import types
import io
import time
import select
import threading
import queue
from concurrent.futures import ThreadPoolExecutor

class SocketWriter(io.IOBase):
    def __init__(self, sock):
        self.sock = sock
        self.buffer = ""
    
    def write(self, data):
        if data:
            # Buffer the data and send on newline
            self.buffer += data
            if '\n' in self.buffer:
                lines = self.buffer.split('\n')
                self.buffer = lines[-1]  # Keep any remaining data without newline
                
                # Send complete lines
                for line in lines[:-1]:
                    if line:  # Only send non-empty lines
                        response = {
                            "type": "output",
                            "data": line + '\n'
                        }
                        self.sock.sendall(json.dumps(response).encode("utf-8") + b"\n")
        return len(data)
    
    def flush(self):
        # Send any remaining buffered data
        if self.buffer:
            response = {
                "type": "output",
                "data": self.buffer
            }
            self.sock.sendall(json.dumps(response).encode("utf-8") + b"\n")
            self.buffer = ""

class ThreadSafeSocketWriter(SocketWriter):
    def __init__(self, sock):
        super().__init__(sock)
        self.lock = threading.Lock()
    
    def write(self, data):
        with self.lock:
            return super().write(data)
    
    def flush(self):
        with self.lock:
            super().flush()

def get_callable_info(obj):
    """Get information about object callables."""
    callables = {}
    try:
        # For dictionaries, we want to show all methods
        show_private = isinstance(obj, dict)
        for name in dir(obj):
            if show_private or not name.startswith('_'):
                try:
                    attr = getattr(obj, name)
                    if callable(attr):
                        # Get full signature including return type annotations if available
                        try:
                            sig = inspect.signature(attr)
                            return_annotation = sig.return_annotation
                            if return_annotation is not inspect.Signature.empty:
                                return_type = return_annotation.__name__ if hasattr(return_annotation, '__name__') else str(return_annotation)
                            else:
                                return_type = None
                        except ValueError:
                            sig = None
                            return_type = None
                        
                        # Determine method type and runnability
                        is_runnable = False
                        if isinstance(attr, staticmethod):
                            method_type = 'static'
                            is_runnable = True
                        elif inspect.isfunction(attr):
                            if isinstance(obj, type) and getattr(obj, name, None) is attr:
                                method_type = 'static'
                                is_runnable = True
                            else:
                                method_type = 'function'
                                is_runnable = not inspect.isclass(obj)
                        elif inspect.ismethod(attr):
                            if attr.__self__ is obj:
                                method_type = 'class'
                                is_runnable = True
                            else:
                                method_type = 'instance'
                                is_runnable = not inspect.isclass(obj)
                        else:
                            method_type = 'other'
                            is_runnable = True
                        
                        # Get source if available
                        try:
                            source = inspect.getsource(attr) if inspect.isfunction(attr) or inspect.ismethod(attr) else None
                        except (TypeError, OSError):
                            source = None
                        
                        # Get parameter count to help determine runnability
                        try:
                            params = list(sig.parameters.values()) if sig else []
                            required_params = sum(1 for p in params if p.default == inspect.Parameter.empty and p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD))
                            # If it requires parameters, it's not directly runnable
                            if required_params > 0:
                                is_runnable = False
                        except:
                            pass
                        
                        callables[name] = {
                            'type': 'method',
                            'method_type': method_type,
                            'callable_type': type(attr).__name__,
                            'is_runnable': is_runnable,
                            'doc': inspect.getdoc(attr) or "No documentation available",
                            'signature': str(sig) if sig else "Signature unavailable",
                            'return_type': return_type,
                            'source_file': inspect.getfile(attr) if inspect.isfunction(attr) else None,
                            'source': source,
                            'is_async': inspect.iscoroutinefunction(attr) or inspect.isasyncgenfunction(attr),
                            'is_generator': inspect.isgeneratorfunction(attr),
                            'is_property': isinstance(attr, property),
                            'decorators': get_decorator_info(attr, obj, name)
                        }
                except Exception as e:
                    callables[name] = {
                        'type': 'error',
                        'error_type': type(e).__name__,
                        'error': str(e)
                    }
    except Exception as e:
        print(f"Error getting callables: {e}")
    return callables

def get_decorator_info(attr, obj, name):
    """Get information about decorators applied to a callable."""
    decorators = []
    try:
        # Check common decorators
        if isinstance(attr, staticmethod):
            decorators.append('@staticmethod')
        elif isinstance(attr, classmethod):
            decorators.append('@classmethod')
        elif isinstance(attr, property):
            decorators.append('@property')
        
        # Try to get source and parse decorators
        try:
            source = inspect.getsource(attr)
            lines = source.split('\n')
            # Look for decorator lines before the def
            for line in lines:
                line = line.strip()
                if line.startswith('def '):
                    break
                if line.startswith('@') and line not in decorators:
                    decorators.append(line)
        except:
            pass
    except:
        pass
    return decorators

def get_attribute_info(obj):
    """Get information about object attributes."""
    attributes = {}
    try:
        # For dictionaries, we want to show all items directly
        if isinstance(obj, dict):
            for key, value in obj.items():
                try:
                    attributes[str(key)] = {
                        'type': type(value).__name__,
                        'category': get_object_category(value),
                        'value': str(value) if not isinstance(value, (dict, list, tuple, set)) else f"{type(value).__name__}({len(value)} items)"
                    }
                except Exception as e:
                    attributes[str(key)] = {
                        'type': 'error',
                        'error_type': type(e).__name__,
                        'error': str(e)
                    }
        else:
            # For non-dictionaries, use dir() as before
            show_private = isinstance(obj, dict)
            for name in dir(obj):
                if show_private or not name.startswith('_'):
                    try:
                        attr = getattr(obj, name)
                        if not callable(attr):
                            attributes[name] = {
                                'type': type(attr).__name__,
                                'category': get_object_category(attr),
                                'value': str(attr) if not isinstance(attr, (dict, list, tuple, set)) else f"{type(attr).__name__}({len(attr)} items)"
                            }
                    except Exception as e:
                        attributes[name] = {
                            'type': 'error',
                            'error_type': type(e).__name__,
                            'error': str(e)
                        }
    except Exception as e:
        print(f"Error getting attributes: {e}")
    return attributes

def get_object_category(obj):
    """Get the category of a Python object."""
    if inspect.ismodule(obj):
        return 'module'
    elif inspect.isclass(obj):
        return 'class'
    elif isinstance(obj, (int, float, complex)):
        return 'number'
    elif isinstance(obj, str):
        return 'string'
    elif isinstance(obj, (list, tuple)):
        return 'sequence'
    elif isinstance(obj, dict):
        return 'dictionary'
    else:
        return 'other'

def get_object_metadata(obj, category):
    """Get metadata about a Python object."""
    metadata = {
        'module': getattr(obj, '__module__', None),
        'qualname': getattr(obj, '__qualname__', None),
        'size': len(obj) if hasattr(obj, '__len__') else None,
        'bases': [base.__name__ for base in obj.__class__.__bases__] if hasattr(obj, '__class__') else None,
    }
    
    # Try to get file location, but handle custom objects gracefully
    try:
        if inspect.ismodule(obj):
            metadata['file'] = inspect.getfile(obj)
        elif inspect.isclass(obj):
            metadata['file'] = inspect.getfile(obj)
        elif inspect.ismethod(obj) or inspect.isfunction(obj):
            metadata['file'] = inspect.getfile(obj)
        else:
            # For instances, try to get the file of their class
            metadata['file'] = inspect.getfile(obj.__class__) if hasattr(obj, '__class__') else None
    except (TypeError, ValueError):
        metadata['file'] = None
    
    if category == 'sequence':
        metadata['length'] = len(obj)
        metadata['element_types'] = list(set(type(x).__name__ for x in obj[:5]))  # Sample first 5 elements
    elif category == 'dictionary':
        metadata['length'] = len(obj)
        metadata['key_types'] = list(set(type(k).__name__ for k in list(obj.keys())[:5]))
        metadata['value_types'] = list(set(type(v).__name__ for v in list(obj.values())[:5]))
    
    return metadata

def get_object_info(obj, path=''):
    """Get detailed information about a Python object."""
    try:
        # Get basic type information
        obj_type = type(obj)
        type_name = obj_type.__name__
        
        # Get object category
        category = get_object_category(obj)
        
        # Get string representation safely
        try:
            str_val = str(obj)
            if len(str_val) > 1000:  # Truncate long strings
                str_val = str_val[:1000] + '...'
        except Exception as e:
            str_val = f"<Error getting string representation: {str(e)}>"

        # Get metadata based on category
        metadata = get_object_metadata(obj, category)
        
        # Get attributes and methods
        attributes = get_attribute_info(obj) if category != 'primitive' else {}
        methods = get_callable_info(obj) if category != 'primitive' else {}
        
        return {
            'type': type_name,
            'category': category,
            'value': str_val,
            'metadata': metadata,
            'attributes': attributes,
            'methods': methods
        }
    except Exception as e:
        return {
            'type': 'error',
            'error_type': type(e).__name__,
            'error': str(e)
        }

def execute_code(code, globals_dict, output_queue):
    # Create a local writer that uses the queue
    class QueueWriter:
        def __init__(self, queue):
            self.queue = queue
            self.buffer = ""
        
        def write(self, data):
            if data:
                self.buffer += data
                if '\n' in self.buffer:
                    lines = self.buffer.split('\n')
                    self.buffer = lines[-1]
                    
                    for line in lines[:-1]:
                        if line:
                            self.queue.put({
                                "type": "output",
                                "data": line + '\n'
                            })
            return len(data)
        
        def flush(self):
            if self.buffer:
                self.queue.put({
                    "type": "output",
                    "data": self.buffer
                })
                self.buffer = ""
    
    # Create local stdout/stderr redirectors
    writer = QueueWriter(output_queue)
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = writer
    sys.stderr = writer
    
    try:
        compiled = compile(code, "<repl>", "single")
        exec(compiled, globals_dict, globals_dict)
        return {"type": "success", "message": "Code executed successfully"}
    except Exception as e:
        err = traceback.format_exc()
        return {"type": "error", "error": err}
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        writer.flush()

def handle_command(cmd, globals_dict, executor, writer, sock, output_queue):
    try:
        if not isinstance(cmd, dict):
            return {"type": "error", "error": "Invalid command format"}
            
        cmd_type = cmd.get("type")
        if not cmd_type:
            return {"type": "error", "error": "No command type specified"}
            
        if cmd_type == "repl":
            code = str(cmd.get("code", ""))
            if not code:
                return {"type": "error", "error": "No code provided"}
            
            def on_complete(future):
                try:
                    result = future.result()
                    sock.sendall(json.dumps(result).encode("utf-8") + b"\n")
                except Exception as e:
                    error_response = {"type": "error", "error": str(e)}
                    sock.sendall(json.dumps(error_response).encode("utf-8") + b"\n")
            
            # Submit code execution to thread pool without blocking
            future = executor.submit(execute_code, code, globals_dict, output_queue)
            future.add_done_callback(on_complete)
            return None  # Don't return a response immediately
                
        elif cmd_type == "inspect":
            try:
                expr = str(cmd.get("expression", ""))
                if not expr:
                    return {"type": "error", "error": "No expression provided"}
                
                # Handle nested attribute access
                parts = []
                current = ""
                in_brackets = False
                for char in expr:
                    if char == '[':
                        if current:
                            parts.append(('attr', current))
                            current = ""
                        in_brackets = True
                    elif char == ']':
                        if current:
                            parts.append(('key', current.strip("'")))
                            current = ""
                        in_brackets = False
                    elif char == '.' and not in_brackets:
                        if current:
                            parts.append(('attr', current))
                            current = ""
                    else:
                        current += char
                if current:
                    parts.append(('attr', current))
                
                # Evaluate the expression part by part
                obj = None
                for i, (access_type, name) in enumerate(parts):
                    if i == 0:
                        # First part is always evaluated in globals
                        obj = eval(name, globals_dict, globals_dict)
                    else:
                        # Subsequent parts are accessed as attributes or keys
                        if access_type == 'key':
                            try:
                                obj = obj[name]  # Try dict-style access first
                            except (TypeError, KeyError):
                                obj = getattr(obj, name)  # Fall back to attribute access
                        else:
                            obj = getattr(obj, name)
                
                info = get_object_info(obj)
                return {"type": "inspect_result", "data": info}
            except Exception as e:
                return {"type": "error", "error": str(e)}
        else:
            return {"type": "error", "error": f"Unknown command type: {cmd_type}"}
    except Exception as e:
        return {"type": "error", "error": f"Command handling error: {str(e)}"}

def connect_socket(host, port, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    r = s.connect_ex((host, port))
    if r not in (0, 10035):
        return None
    
    start_time = time.time()
    while True:
        _, w, _ = select.select([], [s], [], 0.05)
        if s in w:
            e = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if e != 0:
                s.close()
                return None
            return s
        if time.time() - start_time > timeout:
            s.close()
            return None

def run_repl(host, port):
    # Create a thread pool for executing code
    with ThreadPoolExecutor(max_workers=4) as executor:
        while True:
            try:
                s = connect_socket(host, port)
                
                if not s:
                    time.sleep(5)
                    continue

                writer = ThreadSafeSocketWriter(s)
                # Create an output queue instead of redirecting global stdout
                output_queue = queue.Queue()

                response = {
                    "type": "status",
                    "status": "connected",
                    "message": "Python API endpoint ready"
                }
                s.sendall(json.dumps(response).encode("utf-8") + b"\n")

                buf = b""
                running = True

                while running:
                    # Check for output from worker threads
                    try:
                        while True:  # Process all pending output
                            output = output_queue.get_nowait()
                            if output:
                                s.sendall(json.dumps(output).encode("utf-8") + b"\n")
                    except queue.Empty:
                        pass

                    # Check for socket input
                    rs, _, _ = select.select([s], [], [], 0.05)
                    if s in rs:
                        data = s.recv(4096)
                        if not data:
                            break
                        buf += data
                        while b"\n" in buf:
                            line, _, buf = buf.partition(b"\n")
                            try:
                                cmd = json.loads(line.decode("utf-8", "replace"))
                                if cmd.get("type") == "exit":
                                    running = False
                                    response = {"type": "status", "status": "disconnected"}
                                    break
                                
                                response = handle_command(cmd, globals(), executor, writer, s, output_queue)
                                if response:  # Only send immediate responses (non-REPL commands)
                                    s.sendall(json.dumps(response).encode("utf-8") + b"\n")
                            except json.JSONDecodeError:
                                response = {"type": "error", "error": "Invalid JSON"}
                                s.sendall(json.dumps(response).encode("utf-8") + b"\n")
                            except Exception as e:
                                response = {"type": "error", "error": str(e)}
                                s.sendall(json.dumps(response).encode("utf-8") + b"\n")

                s.close()

            except KeyboardInterrupt:
                sys.exit(0)
            except Exception as e:
                print(f"Connection error: {e}")
                
            try:
                s.close()
            except:
                pass
                
            time.sleep(5)

run_repl("__HOST__", __PORT__)
