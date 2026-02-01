# РУКОВОДСТВО ПО ВОССТАНОВЛЕНИЮ ИСХОДНИКОВ ИЗ libclient.so

> **Цель**: Полное руководство по реверс-инжинирингу и восстановлению исходного кода из скомпилированной ARM64 библиотеки

---

## СОДЕРЖАНИЕ

1. [Подготовка инструментов](#этап-1-подготовка-инструментов)
2. [Извлечение данных](#этап-2-извлечение-данных)
3. [Анализ в Ghidra](#этап-3-анализ-в-ghidra)
4. [Анализ в IDA Pro](#этап-4-анализ-в-ida-pro)
5. [Динамический анализ с Frida](#этап-5-динамический-анализ-с-frida)
6. [Анализ сети](#этап-6-анализ-сети)
7. [Восстановление структур](#этап-7-восстановление-структур)
8. [Восстановление логики](#этап-8-восстановление-логики)
9. [Создание рабочего кода](#этап-9-создание-рабочего-кода)
10. [Полезные скрипты](#этап-10-полезные-скрипты)

---

## ЭТАП 1: ПОДГОТОВКА ИНСТРУМЕНТОВ

### 1.1 Базовые инструменты Linux

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    binutils \
    gcc-aarch64-linux-gnu \
    file \
    strings \
    readelf \
    objdump \
    nm \
    strace \
    ltrace
```

### 1.2 Ghidra (GUI декомпилятор)

```bash
# Скачать с GitHub
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip

# Распаковать
unzip ghidra_10.4_PUBLIC_20230928.zip
cd ghidra_10.4_PUBLIC

# Запустить
./ghidraRun
```

**Требования**: Java 17+

### 1.3 radare2 (консольный анализ)

```bash
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

### 1.4 Frida (динамическая инструментация)

```bash
# На компьютере
pip3 install frida frida-tools

# Скачать frida-server для Android ARM64
wget https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz
unxz frida-server-16.1.4-android-arm64.xz
mv frida-server-16.1.4-android-arm64 frida-server
```

### 1.5 Android SDK/NDK

```bash
# Скачать Android Studio или command-line tools
# https://developer.android.com/studio

# Установить NDK через SDK Manager или
wget https://dl.google.com/android/repository/android-ndk-r25c-linux.zip
unzip android-ndk-r25c-linux.zip
export ANDROID_NDK_HOME=$PWD/android-ndk-r25c
```

---

## ЭТАП 2: ИЗВЛЕЧЕНИЕ ДАННЫХ

### 2.1 Извлечение строк

```bash
cd /home/engine/project

# Все ASCII строки
strings libclient.so > strings_all.txt

# Длинные строки (>10 символов)
strings -n 10 libclient.so > strings_long.txt

# Unicode строки (UTF-16)
strings -e l libclient.so > strings_unicode.txt

# Поиск специфичных паттернов
grep -i "http\|url\|api\|key\|token" strings_all.txt > network_strings.txt
grep -i "error\|fail\|success\|warning" strings_all.txt > message_strings.txt
grep "Java_" strings_all.txt > jni_strings.txt
grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" strings_all.txt > ip_strings.txt
```

### 2.2 Извлечение символов

```bash
# Все динамические символы
nm -D libclient.so > symbols_all.txt

# Только функции (TYPE = T)
nm -D libclient.so | grep " T " | awk '{print $3}' > symbols_functions.txt

# Только данные (TYPE = D/B)
nm -D libclient.so | grep " [DB] " | awk '{print $3}' > symbols_data.txt

# С адресами и размерами
nm -D -S --size-sort libclient.so > symbols_sorted_by_size.txt

# Только JNI функции
nm -D libclient.so | grep " T " | grep "Java_" > symbols_jni.txt
```

### 2.3 ELF информация

```bash
# Заголовок ELF
readelf -h libclient.so > elf_header.txt

# Секции
readelf -S libclient.so > elf_sections.txt

# Сегменты программы
readelf -l libclient.so > elf_segments.txt

# Динамические секции
readelf -d libclient.so > elf_dynamic.txt

# Релокации
readelf -r libclient.so > elf_relocations.txt

# Символьные версии
readelf -V libclient.so > elf_versions.txt

# Notes секции
readelf -n libclient.so > elf_notes.txt

# Полный дамп
readelf -a libclient.so > elf_complete.txt
```

### 2.4 Дизассемблирование

```bash
# Требуется aarch64-linux-gnu-objdump

# Полное дизассемблирование
aarch64-linux-gnu-objdump -d libclient.so > disasm_full.asm

# Только .text секция
aarch64-linux-gnu-objdump -d -j .text libclient.so > disasm_text.asm

# С исходными байтами и адресами
aarch64-linux-gnu-objdump -d -S -l libclient.so > disasm_detailed.asm

# С символами
aarch64-linux-gnu-objdump -d -C libclient.so > disasm_demangled.asm
```

### 2.5 Извлечение секций

```bash
# Извлечь .rodata (read-only data)
objcopy --dump-section .rodata=rodata.bin libclient.so

# Извлечь .data (initialized data)
objcopy --dump-section .data=data.bin libclient.so

# Извлечь .text (code)
objcopy --dump-section .text=text.bin libclient.so

# Просмотр в hex
od -A x -t x1z rodata.bin | less
# или
xxd rodata.bin | less
```

---

## ЭТАП 3: АНАЛИЗ В GHIDRA

### 3.1 Импорт файла

1. Запустить Ghidra
2. **File → New Project** (Non-Shared)
3. Указать директорию проекта
4. **File → Import File**
5. Выбрать `libclient.so`
6. Язык: **AARCH64:LE:64:v8A** (автоопределение)
7. OK
8. Double-click на файл в списке
9. Дождаться автоанализа (может занять 10-30 минут)

### 3.2 Навигация

**Основные окна:**
- **Listing**: Дизассемблированный код
- **Decompile**: Декомпилированный C код
- **Symbol Tree**: Дерево символов
- **Functions**: Список функций
- **Data Type Manager**: Типы данных

**Горячие клавиши:**
- `G` - Go to address
- `L` - Label (переименовать)
- `;` - Комментарий
- `Ctrl+L` - Rename
- `Ctrl+Shift+E` - Edit function signature

### 3.3 Поиск JNI функций

```
1. Window → Functions (или нажать F на Symbol Tree)
2. В фильтре ввести: Java_
3. Или Search → For Strings → "Java_"
4. Double-click на функцию для просмотра
```

**Примеры найденных функций:**
- `Java_kentos_loader_floating_FloatService_AimBot`
- `Java_kentos_loader_server_ApiServer_mainURL`

### 3.4 Анализ функции

1. **Выбрать функцию** в списке
2. **Просмотреть декомпиляцию** в окне Decompile
3. **Переименовать переменные**: Правый клик → Rename Variable
4. **Изменить типы**: Правый клик → Retype Variable
5. **Добавить комментарии**: Правый клик → Set Comment
6. **Найти ссылки**: Правый клик → References → Show References to

### 3.5 Построение графа вызовов

```
1. Выбрать функцию
2. Graph → Function Call Graph
3. Изучить связи между функциями
```

### 3.6 Поиск строк

```
Search → For Strings...
Настройки:
- Minimum Length: 4
- String Types: ASCII, UTF-16
- Memory Blocks: .rodata, .data

Полезные фильтры:
- *api*
- *url*
- *key*
- *error*
```

### 3.7 Экспорт

```
File → Export Program
Формат: C/C++
Включить:
- Function definitions
- Data definitions
- Comments
```

---

## ЭТАП 4: АНАЛИЗ В IDA PRO

> **Примечание**: IDA Pro - коммерческое ПО (~$1000+)  
> Альтернатива: IDA Free (ограниченная версия)

### 4.1 Импорт

```
File → Open
Выбрать: libclient.so
Processor: ARM64 (AARCH64)
Analysis options: Default
```

### 4.2 Горячие клавиши

```
G     - Jump to address
X     - Cross-references (кто вызывает функцию)
N     - Rename symbol
;     - Add comment
/     - Add repeatable comment
D     - Convert to data
C     - Convert to code
P     - Create function
A     - Convert to string
F5    - Decompile (Hex-Rays required)
Esc   - Go back
```

### 4.3 Поиск

```
Alt+T - Text search
Alt+B - Binary search
Alt+I - Immediate value search

Ctrl+F - Find в текущем окне
```

### 4.4 Скрипт для экспорта JNI

```python
# ida_export_jni.py
import idaapi
import idc
import idautils

def export_jni_functions():
    """Экспорт всех JNI функций"""
    output = []
    
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        
        if func_name.startswith("Java_"):
            # Получить декомпиляцию (если Hex-Rays доступен)
            try:
                cfunc = idaapi.decompile(func_ea)
                code = str(cfunc)
                
                # Сохранить в файл
                with open(f"jni_{func_name}.c", "w") as f:
                    f.write(f"// Function: {func_name}\n")
                    f.write(f"// Address: 0x{func_ea:x}\n\n")
                    f.write(code)
                
                output.append(func_name)
            except:
                print(f"Failed to decompile: {func_name}")
    
    print(f"Exported {len(output)} JNI functions")
    return output

# Запуск
export_jni_functions()
```

**Использование в IDA:**
```
File → Script File → Выбрать ida_export_jni.py
```

---

## ЭТАП 5: ДИНАМИЧЕСКИЙ АНАЛИЗ С FRIDA

### 5.1 Подготовка Android устройства

```bash
# Подключить устройство через USB
adb devices

# Загрузить frida-server
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server

# Запустить frida-server (требуется root)
adb shell "su -c /data/local/tmp/frida-server &"

# Проверить подключение
frida-ps -U
```

### 5.2 Базовый перехват JNI

```javascript
// hook_basic.js
console.log("[*] Starting Frida hooks...");

Java.perform(function() {
    console.log("[*] Java runtime loaded");
    
    // Хук FloatService
    try {
        var FloatService = Java.use("kentos.loader.floating.FloatService");
        
        // Перехват AimBot
        FloatService.AimingSpeed.implementation = function(speed) {
            console.log("[AimBot] AimingSpeed called with:", speed);
            console.log("[AimBot] Stack trace:", Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()
            ));
            
            // Вызвать оригинальный метод
            this.AimingSpeed(speed);
        };
        
        console.log("[*] FloatService hooks installed");
    } catch(e) {
        console.log("[!] Error hooking FloatService:", e);
    }
});
```

**Запуск:**
```bash
frida -U -l hook_basic.js -f com.kentos.loader
# или для уже запущенного процесса
frida -U -l hook_basic.js "BGMI"
```

### 5.3 Перехват нативных функций

```javascript
// hook_native.js
console.log("[*] Hooking native functions...");

// Найти базовый адрес libclient.so
var base = Module.findBaseAddress("libclient.so");
console.log("[*] libclient.so base:", base);

// Перехват конкретной JNI функции
var aimbot_addr = Module.findExportByName(
    "libclient.so",
    "Java_kentos_loader_floating_FloatService_AimingSpeed"
);

if (aimbot_addr) {
    console.log("[*] Found AimingSpeed at:", aimbot_addr);
    
    Interceptor.attach(aimbot_addr, {
        onEnter: function(args) {
            console.log("\n[Native] AimingSpeed called");
            console.log("  JNIEnv*:", args[0]);
            console.log("  jobject:", args[1]);
            console.log("  jfloat speed:", args[2]);
            
            // Изменить значение (args[2] - это float*)
            // var speed = args[2].readFloat();
            // args[2].writeFloat(10.0);  // Изменить скорость
        },
        onLeave: function(retval) {
            console.log("[Native] AimingSpeed returned");
        }
    });
}

// Перехват malloc для отслеживания аллокаций
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onEnter: function(args) {
        this.size = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.size > 1024*10) {  // Только большие (>10KB)
            console.log("[malloc] Size:", this.size, "Address:", retval);
        }
    }
});

// Перехват API вызовов
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var addr = Socket.peerAddress(sockfd);
        console.log("[network] connect() called");
        console.log("  Socket:", sockfd);
        console.log("  Address:", JSON.stringify(addr));
    }
});
```

### 5.4 Дамп памяти

```javascript
// dump_memory.js

// Дамп всей библиотеки
var base = Module.findBaseAddress("libclient.so");
var size = Process.findModuleByName("libclient.so").size;

console.log("[*] Dumping libclient.so");
console.log("    Base:", base);
console.log("    Size:", size);

var data = Memory.readByteArray(base, size);
var file = new File("/sdcard/libclient_dump.so", "wb");
file.write(data);
file.close();

console.log("[+] Dumped to /sdcard/libclient_dump.so");

// Поиск паттернов в памяти
Memory.scan(base, size, "48 54 54 50", {
    onMatch: function(address, size) {
        console.log("[+] Found 'HTTP' at:", address);
        console.log("    Context:", Memory.readUtf8String(address, 64));
    },
    onComplete: function() {
        console.log("[*] Scan complete");
    }
});
```

### 5.5 Трассировка функций

```javascript
// trace_calls.js

// Трассировка всех JNI вызовов
var module = Process.findModuleByName("libclient.so");

module.enumerateExports().forEach(function(exp) {
    if (exp.name.startsWith("Java_")) {
        console.log("[*] Tracing:", exp.name);
        
        Interceptor.attach(exp.address, {
            onEnter: function() {
                console.log("\n→ Entering:", exp.name);
                console.log("  Thread:", Process.getCurrentThreadId());
                console.log("  Backtrace:\n" + Thread.backtrace(this.context)
                    .map(DebugSymbol.fromAddress).join("\n"));
            },
            onLeave: function() {
                console.log("← Leaving:", exp.name);
            }
        });
    }
});
```

---

## ЭТАП 6: АНАЛИЗ СЕТИ

### 6.1 mitmproxy

```bash
# Установка
pip3 install mitmproxy

# Запуск с веб-интерфейсом
mitmweb -p 8080

# Или консольный режим
mitmproxy -p 8080
```

**Настройка Android:**
1. Settings → WiFi → Long press на сеть → Modify
2. Proxy: Manual
3. Hostname: IP компьютера
4. Port: 8080
5. Открыть http://mitm.it в браузере
6. Установить сертификат

### 6.2 Python addon для mitmproxy

```python
# mitm_addon.py
from mitmproxy import ctx, http

class APIInterceptor:
    def __init__(self):
        self.count = 0
    
    def request(self, flow: http.HTTPFlow):
        # Фильтр по домену/пути
        if "kentos" in flow.request.pretty_url or "api" in flow.request.host:
            self.count += 1
            
            ctx.log.info(f"\n{'='*60}")
            ctx.log.info(f"[REQUEST #{self.count}]")
            ctx.log.info(f"  Method: {flow.request.method}")
            ctx.log.info(f"  URL: {flow.request.pretty_url}")
            ctx.log.info(f"  Headers:")
            for k, v in flow.request.headers.items():
                ctx.log.info(f"    {k}: {v}")
            
            if flow.request.content:
                ctx.log.info(f"  Body ({len(flow.request.content)} bytes):")
                try:
                    ctx.log.info(f"    {flow.request.content.decode('utf-8')}")
                except:
                    ctx.log.info(f"    [Binary data]")
    
    def response(self, flow: http.HTTPFlow):
        if "kentos" in flow.request.pretty_url or "api" in flow.request.host:
            ctx.log.info(f"\n[RESPONSE #{self.count}]")
            ctx.log.info(f"  Status: {flow.response.status_code}")
            ctx.log.info(f"  Headers:")
            for k, v in flow.response.headers.items():
                ctx.log.info(f"    {k}: {v}")
            
            if flow.response.content:
                ctx.log.info(f"  Body ({len(flow.response.content)} bytes):")
                try:
                    ctx.log.info(f"    {flow.response.content.decode('utf-8')}")
                except:
                    ctx.log.info(f"    [Binary data]")

addons = [APIInterceptor()]
```

**Запуск:**
```bash
mitmproxy -s mitm_addon.py -p 8080
```

### 6.3 Wireshark

```bash
# Захват трафика через adb
adb shell "tcpdump -i any -U -w - 2>/dev/null" | wireshark -k -i -
```

**Фильтры:**
- `tcp.port == 443` - HTTPS трафик
- `http` - HTTP трафик
- `ip.dst == 192.168.1.100` - К конкретному серверу

---

## ЭТАП 7: ВОССТАНОВЛЕНИЕ СТРУКТУР

### 7.1 Анализ структур в Ghidra

**Пример: Найти структуру AimBotConfig**

1. Найти функцию `FloatService_SettingAim`
2. Проанализировать доступ к памяти:
   ```c
   *(float *)(param_1 + 0) = aimSpeed;
   *(int *)(param_1 + 4) = targetType;
   *(float *)(param_1 + 8) = smoothness;
   ```
3. Window → Data Type Manager
4. Правый клик → New → Structure
5. Добавить поля согласно offsets

**Результат:**
```c
struct AimBotConfig {
    float aimingSpeed;      // offset 0x00
    int targetType;         // offset 0x04
    float smoothness;       // offset 0x08
    bool enabled;           // offset 0x0C
    float range;            // offset 0x10
    int aimBy;              // offset 0x14
    int aimWhen;            // offset 0x18
};
```

### 7.2 Автоматическое определение структур

**IDA Pro Script:**
```python
import ida_struct
import idc

def create_struct_from_offsets(name, offsets):
    """
    offsets: [(offset, size, name), ...]
    """
    sid = ida_struct.add_struc(-1, name)
    if sid == -1:
        print(f"Failed to create struct {name}")
        return
    
    sptr = ida_struct.get_struc(sid)
    
    for offset, size, field_name in offsets:
        if size == 4:
            flag = idc.FF_DWORD
        elif size == 8:
            flag = idc.FF_QWORD
        elif size == 1:
            flag = idc.FF_BYTE
        else:
            flag = idc.FF_BYTE
        
        ida_struct.add_struc_member(
            sptr, field_name, offset, flag, None, size
        )
    
    print(f"Created struct: {name}")

# Пример использования
create_struct_from_offsets("AimBotConfig", [
    (0x00, 4, "aimingSpeed"),
    (0x04, 4, "targetType"),
    (0x08, 4, "smoothness"),
    (0x0C, 1, "enabled"),
    (0x10, 4, "range"),
])
```

---

## ЭТАП 8: ВОССТАНОВЛЕНИЕ ЛОГИКИ

### 8.1 JNI Сигнатуры

**Общая форма:**
```c
JNIEXPORT <returnType> JNICALL
Java_<package>_<class>_<method>(
    JNIEnv *env,
    jobject thiz,
    <params>...
)
```

**Типы параметров:**
```c
Java type    → JNI type
boolean      → jboolean
byte         → jbyte
char         → jchar
short        → jshort
int          → jint
long         → jlong
float        → jfloat
double       → jdouble
String       → jstring
Object       → jobject
int[]        → jintArray
```

### 8.2 Пример восстановления AimBot

**Ghidra декомпиляция:**
```c
void Java_kentos_loader_floating_FloatService_AimingSpeed
    (JNIEnv *env, jobject thiz, float speed)
{
    *(float *)(&DAT_00360d20 + 0x10) = speed;
    
    if (*(int *)(&DAT_00360d20 + 0x0c) == 1) {
        FUN_001f2340(&DAT_00360d20);
    }
}
```

**Восстановленный код:**
```c
// Глобальная структура
struct AimBotConfig {
    float aimingSpeed;      // 0x00
    int targetType;         // 0x04
    float smoothness;       // 0x08
    bool enabled;           // 0x0C
    float range;            // 0x10
} g_AimBotConfig;

// Функция применения настроек
void ApplyAimBotSettings(struct AimBotConfig* config) {
    // Изменить параметры игры
    GameAimSensitivity = config->aimingSpeed;
    GameAimEnabled = config->enabled;
    // ...
}

// JNI функция
JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_AimingSpeed(
    JNIEnv *env,
    jobject thiz,
    jfloat speed)
{
    // Сохранить в глобальную конфигурацию
    g_AimBotConfig.range = speed;
    
    // Если аимбот включен, применить
    if (g_AimBotConfig.enabled) {
        ApplyAimBotSettings(&g_AimBotConfig);
    }
}
```

### 8.3 Восстановление API функций

**Ghidra декомпиляция:**
```c
jstring Java_kentos_loader_server_ApiServer_mainURL(JNIEnv *env, jobject thiz)
{
    char *decrypted;
    
    decrypted = DecryptString((char *)&DAT_000cd900);
    return (*(*env)->NewStringUTF)(env, decrypted);
}
```

**Восстановленный код:**
```c
// Декодирование XOR
char* DecryptString(const char* encrypted) {
    static char buffer[256];
    const char key[] = "MySecretKey123";
    int keyLen = strlen(key);
    
    int i = 0;
    while (encrypted[i] != '\0') {
        buffer[i] = encrypted[i] ^ key[i % keyLen];
        i++;
    }
    buffer[i] = '\0';
    
    return buffer;
}

// Зашифрованный URL в .rodata
const char ENCRYPTED_URL[] = {
    0x48, 0x65, 0x6c, 0x6c, 0x6f, // "https://api.example.com" XOR key
    0x00
};

JNIEXPORT jstring JNICALL
Java_kentos_loader_server_ApiServer_mainURL(JNIEnv *env, jobject thiz)
{
    char* url = DecryptString(ENCRYPTED_URL);
    return (*env)->NewStringUTF(env, url);
}
```

---

## ЭТАП 9: СОЗДАНИЕ РАБОЧЕГО КОДА

### 9.1 Структура проекта

```
reconstructed_libclient/
├── jni/
│   ├── Android.mk
│   ├── Application.mk
│   ├── main.cpp
│   ├── jni_api_server.cpp
│   ├── jni_float_service.cpp
│   ├── jni_overlay.cpp
│   └── jni_utils.cpp
├── include/
│   ├── jni_functions.h
│   ├── game_structs.h
│   └── config.h
├── game/
│   ├── memory.cpp
│   ├── aimbot.cpp
│   ├── esp.cpp
│   └── recoil.cpp
├── crypto/
│   ├── encryption.cpp
│   └── base64.cpp
├── network/
│   ├── api_client.cpp
│   └── http_client.cpp
└── utils/
    ├── logger.cpp
    └── string_utils.cpp
```

### 9.2 Android.mk

```makefile
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := client
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include

LOCAL_SRC_FILES := \
    main.cpp \
    jni_api_server.cpp \
    jni_float_service.cpp \
    jni_overlay.cpp \
    jni_utils.cpp \
    ../game/memory.cpp \
    ../game/aimbot.cpp \
    ../game/esp.cpp \
    ../game/recoil.cpp \
    ../crypto/encryption.cpp \
    ../crypto/base64.cpp \
    ../network/api_client.cpp \
    ../network/http_client.cpp \
    ../utils/logger.cpp \
    ../utils/string_utils.cpp

LOCAL_LDLIBS := -llog -landroid -lz -ldl
LOCAL_CFLAGS := -O3 -fvisibility=hidden -ffunction-sections -fdata-sections
LOCAL_CPPFLAGS := -std=c++17 -fno-exceptions -fno-rtti
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all

include $(BUILD_SHARED_LIBRARY)
```

### 9.3 Application.mk

```makefile
APP_ABI := arm64-v8a
APP_PLATFORM := android-21
APP_STL := c++_static
APP_CPPFLAGS := -std=c++17 -fno-exceptions -fno-rtti
APP_OPTIM := release
```

### 9.4 Заголовочный файл (jni_functions.h)

```cpp
#ifndef JNI_FUNCTIONS_H
#define JNI_FUNCTIONS_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============= API SERVER =============
JNIEXPORT jstring JNICALL
Java_kentos_loader_server_ApiServer_mainURL(JNIEnv* env, jobject thiz);

JNIEXPORT jstring JNICALL
Java_kentos_loader_server_ApiServer_URLJSON(JNIEnv* env, jobject thiz);

JNIEXPORT void JNICALL
Java_kentos_loader_server_ApiServer_FixCrash(JNIEnv* env, jobject thiz);

JNIEXPORT jstring JNICALL
Java_kentos_loader_server_ApiServer_ApiKeyBox(JNIEnv* env, jobject thiz);

JNIEXPORT jstring JNICALL
Java_kentos_loader_server_ApiServer_EXP(JNIEnv* env, jobject thiz);

JNIEXPORT jstring JNICALL
Java_kentos_loader_server_ApiServer_activity(JNIEnv* env, jobject thiz);

JNIEXPORT jstring JNICALL
Java_kentos_loader_server_ApiServer_getOwner(JNIEnv* env, jobject thiz);

// ============= MAIN ACTIVITY =============
JNIEXPORT void JNICALL
Java_kentos_loader_activity_MainActivity_ONOFFBGMI(
    JNIEnv* env, jobject thiz, jboolean enable);

// ============= FLOAT SERVICE - AIMBOT =============
JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_SettingAim(
    JNIEnv* env, jobject thiz, jint mode);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_AimingSpeed(
    JNIEnv* env, jobject thiz, jfloat speed);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_AimWhen(
    JNIEnv* env, jobject thiz, jint condition);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_AimBy(
    JNIEnv* env, jobject thiz, jint method);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_Smoothness(
    JNIEnv* env, jobject thiz, jfloat value);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_Target(
    JNIEnv* env, jobject thiz, jint type);

// ============= FLOAT SERVICE - WEAPON =============
JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_Bulletspeed(
    JNIEnv* env, jobject thiz, jfloat multiplier);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_recoil(
    JNIEnv* env, jobject thiz, jfloat reduction);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_recoil2(
    JNIEnv* env, jobject thiz, jfloat reduction);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_recoil3(
    JNIEnv* env, jobject thiz, jfloat stabilization);

// ============= FLOAT SERVICE - VISUAL =============
JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_RadarSize(
    JNIEnv* env, jobject thiz, jfloat size);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_Range(
    JNIEnv* env, jobject thiz, jfloat range);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_distances(
    JNIEnv* env, jobject thiz, jboolean show);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_WideView(
    JNIEnv* env, jobject thiz, jfloat fov);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_SkinHack(
    JNIEnv* env, jobject thiz, jboolean enable);

// ============= FLOAT SERVICE - MEMORY =============
JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_SettingMemory(
    JNIEnv* env, jobject thiz, jlong address, jlong value);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_SettingValue(
    JNIEnv* env, jobject thiz, jlong offset, jint value);

// ============= FLOAT SERVICE - TOUCH =============
JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_TouchPosX(
    JNIEnv* env, jobject thiz, jfloat x);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_TouchPosY(
    JNIEnv* env, jobject thiz, jfloat y);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_TouchSize(
    JNIEnv* env, jobject thiz, jfloat size);

// ============= OVERLAY =============
JNIEXPORT void JNICALL
Java_kentos_loader_floating_Overlay_Close(JNIEnv* env, jobject thiz);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_Overlay_DrawOn(
    JNIEnv* env, jobject thiz, jobject canvas);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_Overlay_getReady(JNIEnv* env, jobject thiz);

// ============= TOGGLES =============
JNIEXPORT void JNICALL
Java_kentos_loader_floating_ToggleAim_ToggleAim(
    JNIEnv* env, jobject thiz, jboolean enable);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_ToggleBullet_ToggleBullet(
    JNIEnv* env, jobject thiz, jboolean enable);

JNIEXPORT void JNICALL
Java_kentos_loader_floating_ToggleSimulation_ToggleSimulation(
    JNIEnv* env, jobject thiz, jboolean enable);

// ============= COMPONENTS =============
JNIEXPORT jstring JNICALL
Java_kentos_loader_Component_DownloadZip_pw(JNIEnv* env, jobject thiz);

// ============= UTILS =============
JNIEXPORT jstring JNICALL
Java_com_rei_pro_Component_Utils_sign(
    JNIEnv* env, jobject thiz, jstring data);

#ifdef __cplusplus
}
#endif

#endif // JNI_FUNCTIONS_H
```

### 9.5 Реализация (пример jni_float_service.cpp)

```cpp
#include "jni_functions.h"
#include "game/aimbot.h"
#include "game/recoil.h"
#include "utils/logger.h"

// Глобальная конфигурация
struct {
    struct {
        int mode;
        float speed;
        int when;
        int by;
        float smoothness;
        int target;
        bool enabled;
    } aimbot;
    
    struct {
        float bulletspeed;
        float recoilX;
        float recoilY;
        float stabilization;
    } weapon;
    
    struct {
        float radarSize;
        float range;
        bool showDistances;
        float fov;
        bool skinHack;
    } visual;
} g_Config = {0};

// ============= AIMBOT =============

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_SettingAim(
    JNIEnv* env, jobject thiz, jint mode)
{
    LOGD("SettingAim: mode=%d", mode);
    g_Config.aimbot.mode = mode;
    
    if (g_Config.aimbot.enabled) {
        UpdateAimBotConfig(&g_Config.aimbot);
    }
}

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_AimingSpeed(
    JNIEnv* env, jobject thiz, jfloat speed)
{
    LOGD("AimingSpeed: speed=%.2f", speed);
    g_Config.aimbot.speed = speed;
    
    if (g_Config.aimbot.enabled) {
        SetAimSpeed(speed);
    }
}

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_Smoothness(
    JNIEnv* env, jobject thiz, jfloat value)
{
    LOGD("Smoothness: value=%.2f", value);
    g_Config.aimbot.smoothness = value;
    
    if (g_Config.aimbot.enabled) {
        SetAimSmoothness(value);
    }
}

// ============= WEAPON =============

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_recoil(
    JNIEnv* env, jobject thiz, jfloat reduction)
{
    LOGD("recoil: reduction=%.2f", reduction);
    g_Config.weapon.recoilX = reduction;
    ApplyRecoilReduction(reduction, g_Config.weapon.recoilY);
}

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_Bulletspeed(
    JNIEnv* env, jobject thiz, jfloat multiplier)
{
    LOGD("Bulletspeed: multiplier=%.2f", multiplier);
    g_Config.weapon.bulletspeed = multiplier;
    SetBulletSpeedMultiplier(multiplier);
}

// ============= VISUAL =============

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_WideView(
    JNIEnv* env, jobject thiz, jfloat fov)
{
    LOGD("WideView: fov=%.2f", fov);
    g_Config.visual.fov = fov;
    SetFieldOfView(fov);
}

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_SkinHack(
    JNIEnv* env, jobject thiz, jboolean enable)
{
    LOGD("SkinHack: enable=%d", enable);
    g_Config.visual.skinHack = enable;
    UnlockAllSkins(enable);
}

// ============= MEMORY =============

JNIEXPORT void JNICALL
Java_kentos_loader_floating_FloatService_SettingMemory(
    JNIEnv* env, jobject thiz, jlong address, jlong value)
{
    LOGD("SettingMemory: addr=0x%lx value=0x%lx", address, value);
    
    // Проверка адреса
    if (!IsValidGameAddress((void*)address)) {
        LOGE("Invalid address: 0x%lx", address);
        return;
    }
    
    // Запись в память
    WriteMemory((void*)address, (void*)&value, sizeof(value));
}
```

### 9.6 Компиляция

```bash
cd reconstructed_libclient

# Установить переменные окружения
export ANDROID_NDK_HOME=/path/to/android-ndk
export PATH=$ANDROID_NDK_HOME:$PATH

# Компилировать
ndk-build

# Результат в:
# libs/arm64-v8a/libclient.so

# Проверить размер
ls -lh libs/arm64-v8a/libclient.so

# Проверить символы
nm -D libs/arm64-v8a/libclient.so | grep Java_
```

---

## ЭТАП 10: ПОЛЕЗНЫЕ СКРИПТЫ

### 10.1 Автоматическое извлечение (Bash)

```bash
#!/bin/bash
# extract_all.sh

LIBFILE="libclient.so"
OUTDIR="extracted_$(date +%Y%m%d_%H%M%S)"

echo "[*] Creating output directory: $OUTDIR"
mkdir -p $OUTDIR

echo "[*] Extracting strings..."
strings $LIBFILE > $OUTDIR/strings.txt
strings -e l $LIBFILE > $OUTDIR/strings_unicode.txt
strings $LIBFILE | grep "Java_" > $OUTDIR/jni_functions.txt

echo "[*] Extracting symbols..."
nm -D $LIBFILE > $OUTDIR/symbols.txt
nm -D $LIBFILE | grep " T " | awk '{print $3}' > $OUTDIR/functions.txt
nm -D -S --size-sort $LIBFILE > $OUTDIR/functions_sorted.txt

echo "[*] Extracting ELF info..."
readelf -h $LIBFILE > $OUTDIR/elf_header.txt
readelf -S $LIBFILE > $OUTDIR/elf_sections.txt
readelf -d $LIBFILE > $OUTDIR/elf_dynamic.txt
readelf -a $LIBFILE > $OUTDIR/elf_full.txt

echo "[*] Extracting sections..."
objcopy --dump-section .rodata=$OUTDIR/rodata.bin $LIBFILE 2>/dev/null
objcopy --dump-section .data=$OUTDIR/data.bin $LIBFILE 2>/dev/null
objcopy --dump-section .text=$OUTDIR/text.bin $LIBFILE 2>/dev/null

echo "[*] Analyzing dependencies..."
objdump -p $LIBFILE | grep NEEDED > $OUTDIR/dependencies.txt

echo "[*] Searching for patterns..."
strings $LIBFILE | grep -iE "http|https|api|url|key|token" > $OUTDIR/network_strings.txt
strings $LIBFILE | grep -iE "error|fail|success|warning" > $OUTDIR/messages.txt
strings $LIBFILE | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" > $OUTDIR/ip_addresses.txt

echo "[+] Extraction complete! Results in: $OUTDIR/"
echo "[+] Summary:"
echo "    Strings: $(wc -l < $OUTDIR/strings.txt)"
echo "    Functions: $(wc -l < $OUTDIR/functions.txt)"
echo "    JNI functions: $(wc -l < $OUTDIR/jni_functions.txt)"
```

### 10.2 Поиск ключевых данных (Bash)

```bash
#!/bin/bash
# find_secrets.sh

LIBFILE="libclient.so"

echo "╔════════════════════════════════════════╗"
echo "║  Searching for secrets in libclient.so ║"
echo "╚════════════════════════════════════════╝"

echo -e "\n[+] URLs and Endpoints:"
strings $LIBFILE | grep -E "^http|^https|^ftp|^ws://"

echo -e "\n[+] API related:"
strings $LIBFILE | grep -i "api" | head -20

echo -e "\n[+] Keys and tokens:"
strings $LIBFILE | grep -iE "key|token|secret|password|pwd" | head -20

echo -e "\n[+] Email addresses:"
strings $LIBFILE | grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

echo -e "\n[+] Base64 patterns (potential encoded data):"
strings $LIBFILE | grep -E "^[A-Za-z0-9+/]{40,}={0,2}$" | head -10

echo -e "\n[+] File paths:"
strings $LIBFILE | grep "/" | head -20

echo -e "\n[+] JSON patterns:"
strings $LIBFILE | grep -E '\{.*:.*\}' | head -10
```

### 10.3 Генерация заголовочных файлов (Python)

```python
#!/usr/bin/env python3
# generate_headers.py

import subprocess
import re

def get_jni_functions(libfile):
    """Извлечь все JNI функции из библиотеки"""
    result = subprocess.run(
        ["nm", "-D", libfile],
        capture_output=True,
        text=True
    )
    
    functions = []
    for line in result.stdout.split('\n'):
        if ' T ' in line and 'Java_' in line:
            parts = line.split()
            if len(parts) >= 3:
                functions.append(parts[2])
    
    return sorted(set(functions))

def jni_to_signature(func_name):
    """Преобразовать имя JNI функции в сигнатуру"""
    # Java_package_Class_method → package.Class.method
    parts = func_name.split('_')
    
    if len(parts) < 4 or parts[0] != 'Java':
        return None
    
    package = '.'.join(parts[1:-2])
    class_name = parts[-2]
    method = parts[-1]
    
    return {
        'full_name': func_name,
        'package': package,
        'class': class_name,
        'method': method
    }

def generate_header(functions):
    """Генерировать заголовочный файл"""
    header = """#ifndef JNI_FUNCTIONS_AUTO_H
#define JNI_FUNCTIONS_AUTO_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// Auto-generated JNI function declarations
// Total functions: {}

""".format(len(functions))
    
    current_class = None
    
    for func in functions:
        sig = jni_to_signature(func)
        if not sig:
            continue
        
        # Добавить комментарий с именем класса
        if sig['class'] != current_class:
            header += f"\n// ============= {sig['class']} =============\n\n"
            current_class = sig['class']
        
        # Добавить прототип
        header += f"JNIEXPORT void JNICALL\n{func}(JNIEnv* env, jobject thiz);\n\n"
    
    header += """
#ifdef __cplusplus
}
#endif

#endif // JNI_FUNCTIONS_AUTO_H
"""
    
    return header

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 generate_headers.py libclient.so")
        sys.exit(1)
    
    libfile = sys.argv[1]
    
    print(f"[*] Analyzing {libfile}...")
    functions = get_jni_functions(libfile)
    
    print(f"[*] Found {len(functions)} JNI functions")
    
    header = generate_header(functions)
    
    output_file = "jni_functions_auto.h"
    with open(output_file, 'w') as f:
        f.write(header)
    
    print(f"[+] Header generated: {output_file}")
```

---

## ЗАКЛЮЧЕНИЕ

### Что можно восстановить полностью:
✅ Структуру JNI функций (имена, параметры)  
✅ Строки и константы  
✅ Экспортированные функции  
✅ Структуры данных (с анализом)  
✅ Общую логику работы  

### Что требует работы:
⚠️ Внутренние алгоритмы (дизассемблирование)  
⚠️ Имена локальных переменных (потеряны)  
⚠️ Комментарии (не сохраняются)  
⚠️ Оптимизация кода  

### Оценка времени:
- **Базовая структура**: 1-2 дня
- **Декомпиляция функций**: 1-2 недели
- **Полное понимание**: 1-2 месяца
- **Рабочая копия**: 2-3 месяца

### Следующие шаги:
1. ✅ Извлечь все данные с помощью скриптов
2. ✅ Проанализировать в Ghidra/IDA
3. ✅ Использовать Frida для динамического анализа
4. ✅ Перехватить сетевой трафик
5. ✅ Восстановить структуры данных
6. ✅ Написать рабочий код
7. ✅ Протестировать на устройстве

---

**Последнее обновление**: Февраль 2026  
**Версия документа**: 1.0
