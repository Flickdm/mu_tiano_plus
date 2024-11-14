from edk2toollib.utility_functions import export_c_type_array



with open('PlatformKey.der', 'rb') as fr:
    with open("PlatformKey.h", 'w') as fw:
        fw.write("#ifndef PLATFORM_KEY_H_\n")
        fw.write("#define PLATFORM_KEY_H_\n\n")
        export_c_type_array(fr, "PlatformKey", fw)
        fw.write("#endif // PLATFORM_KEY_H_\n")