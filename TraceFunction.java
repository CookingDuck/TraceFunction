package com.open;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.FunctionCallListener;
import com.github.unidbg.pointer.UnidbgPointer;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class TraceFunction {
    private final Emulator<?> emulator;
    private final String outPutPath;
    private final RegisterContext registerContext;
    private final Module module;
    private final int arg_len;
    private final int windowSize;
    private final boolean showRets;

    public TraceFunction(Emulator<?> emulator, Module module, String outPutPath) {
        this.emulator = emulator;
        this.module = module;
        this.outPutPath = outPutPath;
        this.windowSize = 80;
        this.registerContext = emulator.getContext();
        this.arg_len = 4;
        this.showRets = true;
        trace_function();
    }

    public TraceFunction(Emulator<?> emulator, Module module, String outPutPath, int arg_len) {
        this.emulator = emulator;
        this.module = module;
        this.outPutPath = outPutPath;
        this.windowSize = 80;
        this.registerContext = emulator.getContext();
        this.showRets = true;
        this.arg_len = arg_len;
        trace_function();
    }

    public TraceFunction(Emulator<?> emulator, Module module, String outPutPath, boolean showRets) {
        this.emulator = emulator;
        this.module = module;
        this.outPutPath = outPutPath;
        this.windowSize = 80;
        this.registerContext = emulator.getContext();
        this.showRets = showRets;
        this.arg_len = 4;
        trace_function();
    }

    public TraceFunction(Emulator<?> emulator, Module module, String outPutPath, int arg_len, boolean showRets) {
        this.emulator = emulator;
        this.module = module;
        this.outPutPath = outPutPath;
        this.windowSize = 80;
        this.registerContext = emulator.getContext();
        this.showRets = showRets;
        this.arg_len = arg_len;
        trace_function();
    }

    public TraceFunction(Emulator<?> emulator, Module module, String outPutPath, int arg_len, boolean showRets, int windowSize) {
        this.emulator = emulator;
        this.module = module;
        this.outPutPath = outPutPath;
        this.windowSize = windowSize;
        this.registerContext = emulator.getContext();
        this.showRets = showRets;
        this.arg_len = arg_len;
        trace_function();
    }


    public void trace_function() {
        Debugger debugger = emulator.attach();
        PrintStream traceStream = null;
        try {
            // 保存文件
            traceStream = new PrintStream(new FileOutputStream(outPutPath, false));  // false 表示覆盖写入
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        final PrintStream finalTraceStream = traceStream;
        assert finalTraceStream != null;
        debugger.traceFunctionCall(null, new FunctionCallListener() {
            @Override
            public void onCall(Emulator<?> emulator, long callerAddress, long functionAddress) {
                try {
                    StringBuilder pcString = new StringBuilder("          ");
                    pcString.append(registerContext.getPCPointer().toString());
                    while (pcString.length() < 59) {
                        pcString.append(" ");
                    }
                    pcString.append("sub: 0x" + Long.toHexString(functionAddress - module.base));
                    writeFuncToFile(pcString + "\n");
                    for (int i = 0; i < arg_len; i++) {
                        UnidbgPointer args = registerContext.getPointerArg(i);
                        byte[] readBytes;
                        try {
                            readBytes = emulator.getBackend().mem_read(args.peer, windowSize);
                        } catch (Exception e) {
                            readBytes = new byte[16];
                        }
                        writeArgToFile(readBytes, i, args.peer);
                    }
                } catch (Exception e) {
                }
            }

            @Override
            public void postCall(Emulator<?> emulator, long callerAddress, long functionAddress, Number[] args) {
                if (showRets) {
                    try {
                        StringBuilder pcString = new StringBuilder("          ");
                        pcString.append(registerContext.getPCPointer().toString());
                        while (pcString.length() < 59) {
                            pcString.append(" ");
                        }
                        pcString.append("call sub: 0x" + Long.toHexString(functionAddress - module.base));
                        writeFuncToFile(pcString + "\n");
                        if (args != null && args.length > 0) {
                            for (int l = 0; l < args.length; l++) {
                                byte[] readBytes;
                                UnidbgPointer pointer = UnidbgPointer.pointer(emulator, args[l].longValue());
                                try {
                                    readBytes = pointer.getByteArray(0, windowSize);
                                } catch (Exception e) {
                                    readBytes = new byte[16];
                                }
                                writeRetArgToFile(readBytes, l, pointer.peer);
                            }
                        }
                        byte[] retBytes;
                        long lrPoint = registerContext.getLR();
                        try {
                            retBytes = emulator.getBackend().mem_read(lrPoint, windowSize);
                        } catch (Exception e) {
                            retBytes = new byte[16];
                        }
                        writeRetToFile(retBytes, lrPoint);
                    } catch (Exception e) {

                    }
                }
            }
        });
    }

    // 立即将数据写入文件
    private void writeArgToFile(byte[] data, int args, long baseAddress) {
        Path outputPath = Paths.get(this.outPutPath);
        try (OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(outputPath, StandardOpenOption.CREATE, StandardOpenOption.APPEND))) {
            String separator = String.format("\n--------  -----------------------------------------------  ---------------- arg %d\n", args);
            outputStream.write(separator.getBytes());
            String formattedHex = formatHexOutput(data, baseAddress);
            outputStream.write(formattedHex.getBytes());
            outputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeRetToFile(byte[] data, long baseAddress) {
        Path outputPath = Paths.get(this.outPutPath);
        try (OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(outputPath, StandardOpenOption.CREATE, StandardOpenOption.APPEND))) {
            String separator = String.format("\n--------  -----------------------------------------------  ---------------- retValue \n");
            outputStream.write(separator.getBytes());
            String formattedHex = formatHexOutput(data, baseAddress);
            outputStream.write(formattedHex.getBytes());
            outputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeRetArgToFile(byte[] data, int args, long baseAddress) {
        Path outputPath = Paths.get(this.outPutPath);
        try (OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(outputPath, StandardOpenOption.CREATE, StandardOpenOption.APPEND))) {
            String separator = String.format("\n--------  -----------------------------------------------  ---------------- retArg %d\n", args);
            outputStream.write(separator.getBytes());
            String formattedHex = formatHexOutput(data, baseAddress);
            outputStream.write(formattedHex.getBytes());
            outputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void writeFuncToFile(String data) {
        Path outputPath = Paths.get(this.outPutPath);
        try (OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(outputPath, StandardOpenOption.CREATE, StandardOpenOption.APPEND))) {
            String separator = "\n\n========  ===============================================  =========== func\n";
            outputStream.write(separator.getBytes());
            outputStream.write(data.getBytes());
            outputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String formatHexOutput(byte[] bytes, long baseAddress) {
        StringBuilder sb = new StringBuilder();
        int length = bytes.length;
        for (int i = 0; i < length; i += 16) {
            sb.append(String.format("%08X  ", baseAddress + i));
            for (int j = 0; j < 16; j++) {
                if (i + j < length) {
                    sb.append(String.format("%02X ", bytes[i + j]));
                } else {
                    sb.append("   ");
                }
            }
            sb.append(" ");
            for (int j = 0; j < 16; j++) {
                if (i + j < length) {
                    byte b = bytes[i + j];
                    if (b >= 32 && b <= 126) {
                        sb.append((char) b);
                    } else {
                        sb.append('.');
                    }
                } else {
                    sb.append(" ");
                }
            }
            sb.append(System.lineSeparator());
        }
        return sb.toString();
    }
}
