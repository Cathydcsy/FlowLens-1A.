# Third-party components

The FlowLens source is MIT licensed. Third-party libraries retain their own licenses.

| Component | Role | License and corresponding source |
|---|---|---|
| Qt 5.9.6 / Qt Widgets / Qt SVG | Unmodified dynamically linked GUI libraries | LGPL-3.0; https://download.qt.io/archive/qt/5.9/5.9.6/submodules/ and https://code.qt.io/cgit/qt/qtbase.git/tree/?h=v5.9.6 |
| ICU 58.2 | Qt Unicode support | ICU license; https://github.com/unicode-org/icu/tree/release-58-2 |
| zlib | Qt compression support | zlib license; https://zlib.net/zlib_license.html |
| libpng | Qt PNG support | libpng license; http://www.libpng.org/pub/png/src/libpng-LICENSE.txt |
| ANGLE | Qt OpenGL support DLLs, when deployed by windeployqt | BSD-style license; Qt qtbase v5.9.6 src/3rdparty/angle/LICENSE |
| Microsoft Visual C++ runtime | Application runtime | Microsoft redistributable terms; install an official supported VC++ Redistributable if absent |
| Npcap 1.90 | Installed separately for live capture | Npcap license; https://npcap.com/ ; driver and installer are not redistributed |

Qt library files are unmodified and dynamically linked. Source and build files for FlowLens are supplied, allowing rebuilding/relinking against a compatible replacement Qt installation. No restriction is imposed on reverse engineering for debugging modifications to the LGPL library. The applicable LGPL/GPL texts are in `licenses/`. Qt source corresponding to this version is publicly available at the links above; the conda package is `qt-5.9.6-vc14h1e9a669_2` from Anaconda defaults.

Scapy, psutil, clang-format, imageio-ffmpeg, ReportLab, and Pillow are development/verification/documentation tools. Their cached distributions are excluded from the source and submission package. The video uses the Windows installed Huihui synthesized voice; no remote speech service is used.
