# БЫСТРЫЙ СТАРТ: Анализ libclient.so

> **Краткое руководство для быстрого начала работы**

---

## ЧТО ЭТО ЗА ФАЙЛ?

**libclient.so** - нативная ARM64 библиотека для Android, часть чит-приложения для игры BGMI (Battlegrounds Mobile India).

### Основная информация:
- **Размер**: 3.4 MB
- **Архитектура**: ARM64 (aarch64)
- **Функций**: ~5,191 экспортированных
- **JNI функций**: 36
- **Содержит**: OpenSSL + читы для игры

---

## БЫСТРЫЙ АНАЛИЗ (5 МИНУТ)

### 1. Базовая информация
```bash
cd /home/engine/project

# Тип файла
file libclient.so

# Размер и секции
size libclient.so

# Зависимости
ldd libclient.so  # или:
readelf -d libclient.so | grep NEEDED
```

### 2. Найти JNI функции
```bash
# Все JNI функции
strings libclient.so | grep "^Java_"

# Количество
strings libclient.so | grep "^Java_" | wc -l
```

**Результат**: 36 JNI функций для читов

### 3. Основные категории
```bash
# AimBot функции
strings libclient.so | grep "Java_.*Aim"

# API функции
strings libclient.so | grep "Java_.*ApiServer"

# Оверлей
strings libclient.so | grep "Java_.*Overlay"
```

---

## ИЗВЛЕЧЕНИЕ ДАННЫХ (15 МИНУТ)

### Автоматический скрипт
```bash
#!/bin/bash
# quick_extract.sh

LIBFILE="libclient.so"
OUTDIR="analysis_output"
mkdir -p $OUTDIR

# Строки
strings $LIBFILE > $OUTDIR/strings.txt
strings $LIBFILE | grep "Java_" > $OUTDIR/jni_functions.txt

# Символы
nm -D $LIBFILE | grep " T " > $OUTDIR/functions.txt

# ELF инфо
readelf -h $LIBFILE > $OUTDIR/elf_header.txt
readelf -S $LIBFILE > $OUTDIR/elf_sections.txt

echo "Done! Check $OUTDIR/"
```

**Запуск:**
```bash
chmod +x quick_extract.sh
./quick_extract.sh
```

---

## ДЕКОМПИЛЯЦИЯ В GHIDRA (30 МИНУТ)

### 1. Установка Ghidra
```bash
# Скачать с https://ghidra-sre.org/
# Требуется Java 17+

./ghidraRun
```

### 2. Импорт файла
1. **File → New Project** → Non-Shared
2. **File → Import File** → Выбрать `libclient.so`
3. Язык: **AARCH64:LE:64:v8A**
4. **Анализировать** (подождать 10-15 минут)

### 3. Найти JNI функции
```
1. Window → Functions (или Symbol Tree)
2. Filter: "Java_"
3. Double-click на функцию
4. Смотреть декомпиляцию в окне "Decompile"
```

### 4. Быстрый анализ AimBot
```
1. Найти: Java_kentos_loader_floating_FloatService_AimingSpeed
2. Смотреть что функция делает
3. Найти ссылки на глобальные переменные
4. Построить граф: Graph → Function Call Graph
```

---

## ДИНАМИЧЕСКИЙ АНАЛИЗ С FRIDA (20 МИНУТ)

### 1. Установка Frida
```bash
# На компьютере
pip3 install frida frida-tools

# Frida-server на Android (требуется root)
# Скачать с https://github.com/frida/frida/releases
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "su -c /data/local/tmp/frida-server &"
```

### 2. Базовый перехват
```javascript
// hook.js
Java.perform(function() {
    var FloatService = Java.use("kentos.loader.floating.FloatService");
    
    FloatService.AimingSpeed.implementation = function(speed) {
        console.log("[AimBot] Speed:", speed);
        this.AimingSpeed(speed);
    };
});
```

### 3. Запуск
```bash
frida -U -l hook.js "BGMI"
```

---

## ЧТО МОЖНО НАЙТИ?

### ✅ Легко найти:
1. **JNI функции** (36 штук)
   - Имена функций
   - Какие параметры принимают
   - К каким Java классам относятся

2. **Строки** (22,863 строк)
   - URL серверов (возможно зашифрованы)
   - Сообщения об ошибках
   - Имена файлов

3. **Функции читов**:
   - AimBot (автоприцеливание)
   - ESP (видимость врагов)
   - Recoil control (без отдачи)
   - Skin hacks (разблокировка скинов)

### ⚠️ Требует работы:
1. **Алгоритмы** - нужна декомпиляция
2. **API endpoints** - могут быть зашифрованы
3. **Ключи** - поиск в памяти
4. **Протоколы** - анализ трафика

---

## ПОЛЕЗНЫЕ КОМАНДЫ

### Поиск конкретных данных
```bash
# URL и API
strings libclient.so | grep -i "http\|url\|api"

# Ключи и пароли
strings libclient.so | grep -i "key\|token\|password"

# IP адреса
strings libclient.so | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"

# Функции шифрования
nm -D libclient.so | grep -i "encrypt\|decrypt\|aes\|rsa"
```

### Сравнение с оригиналом
```bash
# Если вы пересобрали библиотеку
md5sum libclient.so reconstructed.so
diff <(nm -D libclient.so) <(nm -D reconstructed.so)
```

---

## СПИСОК JNI ФУНКЦИЙ

### API (7 функций)
```
Java_kentos_loader_server_ApiServer_mainURL
Java_kentos_loader_server_ApiServer_URLJSON
Java_kentos_loader_server_ApiServer_ApiKeyBox
Java_kentos_loader_server_ApiServer_EXP
Java_kentos_loader_server_ApiServer_activity
Java_kentos_loader_server_ApiServer_FixCrash
Java_kentos_loader_server_ApiServer_getOwner
```

### Читы - AimBot (6 функций)
```
Java_kentos_loader_floating_FloatService_SettingAim
Java_kentos_loader_floating_FloatService_AimingSpeed
Java_kentos_loader_floating_FloatService_AimWhen
Java_kentos_loader_floating_FloatService_AimBy
Java_kentos_loader_floating_FloatService_Smoothness
Java_kentos_loader_floating_FloatService_Target
```

### Читы - Оружие (4 функции)
```
Java_kentos_loader_floating_FloatService_Bulletspeed
Java_kentos_loader_floating_FloatService_recoil
Java_kentos_loader_floating_FloatService_recoil2
Java_kentos_loader_floating_FloatService_recoil3
```

### Читы - ESP (5 функций)
```
Java_kentos_loader_floating_FloatService_RadarSize
Java_kentos_loader_floating_FloatService_Range
Java_kentos_loader_floating_FloatService_distances
Java_kentos_loader_floating_FloatService_WideView
Java_kentos_loader_floating_FloatService_SkinHack
```

### Память (2 функции)
```
Java_kentos_loader_floating_FloatService_SettingMemory
Java_kentos_loader_floating_FloatService_SettingValue
```

### Прочие (12 функций)
```
Java_kentos_loader_activity_MainActivity_ONOFFBGMI
Java_kentos_loader_floating_Overlay_Close
Java_kentos_loader_floating_Overlay_DrawOn
Java_kentos_loader_floating_Overlay_getReady
Java_kentos_loader_floating_ToggleAim_ToggleAim
Java_kentos_loader_floating_ToggleBullet_ToggleBullet
Java_kentos_loader_floating_ToggleSimulation_ToggleSimulation
Java_kentos_loader_floating_FloatService_TouchPosX
Java_kentos_loader_floating_FloatService_TouchPosY
Java_kentos_loader_floating_FloatService_TouchSize
Java_kentos_loader_Component_DownloadZip_pw
Java_com_rei_pro_Component_Utils_sign
```

---

## ВАЖНЫЕ ФАЙЛЫ В ПРОЕКТЕ

После анализа вы найдете:

1. **FULL_ANALYSIS_REPORT.md** - полный отчет (10+ страниц)
2. **JNI_FUNCTIONS_LIST.md** - подробный список всех JNI функций
3. **REVERSE_ENGINEERING_GUIDE.md** - пошаговое руководство (30+ страниц)
4. **QUICK_START_GUIDE.md** - этот файл

---

## СЛЕДУЮЩИЕ ШАГИ

### Для понимания:
1. ✅ Прочитать FULL_ANALYSIS_REPORT.md
2. ✅ Изучить JNI_FUNCTIONS_LIST.md
3. ✅ Извлечь строки и символы (скрипты выше)

### Для углубленного анализа:
1. ⚠️ Загрузить в Ghidra для декомпиляции
2. ⚠️ Использовать Frida для динамического анализа
3. ⚠️ Проанализировать сетевой трафик с mitmproxy

### Для восстановления:
1. ❌ Следовать REVERSE_ENGINEERING_GUIDE.md
2. ❌ Восстановить структуры данных
3. ❌ Написать рабочий код на C++
4. ❌ Скомпилировать с Android NDK

---

## РЕКОМЕНДУЕМЫЕ ИНСТРУМЕНТЫ

### Бесплатные:
- **Ghidra** - декомпиляция (лучший бесплатный)
- **radare2** - консольный анализ
- **Frida** - динамическая инструментация
- **mitmproxy** - перехват трафика
- **Wireshark** - анализ сети

### Платные:
- **IDA Pro** - профессиональный декомпилятор ($1000+)
- **Binary Ninja** - современный анализатор ($300+)
- **Hopper** - декомпилятор для Mac ($100+)

---

## ПРЕДУПРЕЖДЕНИЯ

### ⚠️ Юридические аспекты:
- Это **чит для онлайн-игры**
- Использование нарушает ToS игры
- Возможен **бан аккаунта**
- Может быть **незаконно** в вашей юрисдикции

### ⚠️ Безопасность:
- Библиотека может содержать **вредоносный код**
- Не устанавливайте на основное устройство
- Используйте **виртуальную машину** или **тестовое устройство**

### ⚠️ Этика:
- Читинг портит опыт другим игрокам
- Анализ должен быть **только для обучения**
- **Не распространяйте** восстановленный код

---

## FAQ

**Q: Можно ли восстановить исходный код полностью?**  
A: Нет. Можно восстановить логику и структуру, но не оригинальный код C++.

**Q: Сколько времени займет полный анализ?**  
A: Базовый анализ - 1 день, полный - 1-2 месяца.

**Q: Нужен ли root на Android для Frida?**  
A: Да, для динамического анализа требуется root.

**Q: Можно ли использовать на обычном компьютере?**  
A: Нет, это ARM64 библиотека для Android. Нужен эмулятор или устройство.

**Q: Что самое важное в этом файле?**  
A: 36 JNI функций - это интерфейс между Java и нативным кодом читов.

---

## КОНТАКТЫ И ПОМОЩЬ

### Документация:
- ARM64 Assembly: https://developer.arm.com/
- JNI Specification: https://docs.oracle.com/javase/8/docs/technotes/guides/jni/
- Android NDK: https://developer.android.com/ndk

### Сообщества:
- r/ReverseEngineering
- r/netsec
- Stack Overflow (тег: reverse-engineering)

### Инструменты:
- Ghidra: https://ghidra-sre.org/
- Frida: https://frida.re/
- radare2: https://rada.re/

---

**Последнее обновление**: Февраль 2026  
**Версия**: 1.0  
**Автор**: AI Security Researcher
