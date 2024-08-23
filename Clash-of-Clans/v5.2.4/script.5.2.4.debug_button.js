/* 
    Created by wisedev
    8/21/24 9:17 AM
*/

var stage_address;

const Config = {
    Host: "192.168.100.100",
    Port: "1337"
}

const Libg = {
    init() {
        this.lib = Module.findBaseAddress('libg.so');
        log(this.lib);

        this.libc = {
            addr: {
                malloc: Module.findExportByName('libc.so', 'malloc'),
                getaddrinfo: Module.findExportByName('libc.so', 'getaddrinfo'),
                free: Module.findExportByName("libc.so", "free")
            },
            malloc(size) {
                return new NativeFunction(this.addr.malloc, 'pointer', ['int'])(size);
            },
            free(value) {
                return new NativeFunction(Libg.libc.addr.free, 'void', ['pointer'])(value);
            }
        }

        this.ServerConnection = {
            addr: {
                connectTo: Libg.offset("_ZN16ServerConnection9connectToEP6String")
            }
        }

        this.ResourceListener = {
            addr: {
                addFile: Libg.offset("_ZN16ResourceListener7addFileEPKc")
            },
            addFile(ctor, value) {
                return new NativeFunction(Libg.ResourceListener.addr.addFile, "void", ["pointer", "pointer"])(ctor, value);
            }
        }

        this.GameMode = {
            addr: {
                addResourcesToLoad: Libg.offset("_ZN8GameMode18addResourcesToLoadEP16ResourceListener")
            }
        }

        this.Stage = {
            addr: {
                ctor: Libg.offset("_ZN5StageC2Ev"),
                addChild: Libg.offset("_ZN5Stage8addChildEP13DisplayObject"),
                removeChild: Libg.offset("_ZN5Stage11removeChildEP13DisplayObject"),
                instance: Libg.offset("_ZN5Stage12sm_pInstanceE")
            },
            addChild(stage, displayObject) {
                return new NativeFunction(Libg.Stage.addr.addChild, "int", ["pointer", "pointer"])(stage, displayObject);
            },
            removeChild(stage_address, displayObject) {
                return new NativeFunction(Libg.Stage.addr.removeChild, "int", ["pointer", "pointer"])(stage_address, displayObject);
            }
        }

        this.MoneyHud = {
            addr: {
                ctor: Libg.offset("_ZN8MoneyHUDC2EP9MovieClip")
            }
        }

        this.String = {
            addr: {
                ctor: Libg.offset("_ZN6StringC2EPKc")
            },
            ctor(str) {
                var mem = Libg.libc.malloc(32);

                new NativeFunction(this.addr.ctor, 'void', ['pointer', 'pointer'])(mem, str);
                return mem;
            }
        }

        this.MagicButton = {
            addr: {
                ctor: Libg.offset("_ZN11MagicButtonC2Ev")
            },
            ctor(ptr) {
                new NativeFunction(this.addr.ctor, 'void', ['pointer'])(ptr);
            }
        }

        this.MovieClip = {
            addr: {
                getMovieClipByName: Libg.offset("_ZNK9MovieClip18getMovieClipByNameEPKc")
            },
            getMovieClipByName(ptr, exportName) {
                return new NativeFunction(this.addr.getMovieClipByName, 'pointer', ['pointer', 'pointer'])(ptr, exportName);
            }
        }

        this.ResourceManager = {
            addr: {
                getMovieClip: Libg.offset("_ZN15ResourceManager12getMovieClipEPKcS1_")
            },
            getMovieClip(s, s2) {
                return new NativeFunction(this.addr.getMovieClip, 'pointer', ['pointer', 'pointer'])(s, s2);
            }
        }

        this.CustomButton = {
            addr: {
                setMovieClip: Libg.offset("_ZN12CustomButton12setMovieClipEP9MovieClipb")
            },
            setMovieClip(ptr, clip, bool) {
                return new NativeFunction(this.addr.setMovieClip, 'int', ['pointer', 'pointer', 'int'])(ptr, clip, bool);
            }
        }

        this.StringTable = {
            addr: {
                getMovieClip: Libg.offset("_ZN11StringTable12getMovieClipERK6StringS2_")
            },
            getMovieClip(ptr, ptr1) {
                return new NativeFunction(this.addr.getMovieClip, 'pointer', ['pointer', 'pointer'])(ptr, ptr1);
            }
        }

        this.DebugMenu = {
            addr: {
                ctor: Libg.offset("_ZN9DebugMenuC2Ev")
            },
            DebugMenuCtor(ptr) {
                return new NativeFunction(Libg.DebugMenu.addr.ctor, "void", ["pointer"])(ptr);
            }
        }

        this.HUD = {
            addr: {
                update: Libg.offset("_ZN3HUD6updateEf")
            }
        }

        this.DebugMenuBase = {
            addr: {
                update: Libg.offset("_ZN13DebugMenuBase6updateEf")
            },
            DebugMenuBaseUpdate(ptr, fl) {
                return new NativeFunction(Libg.DebugMenuBase.addr.update, "int", ["pointer", "float"])(ptr, fl);
            }
        }

        this.ToggleDebugMenuButton = {
            addr: {
                buttonPressed: Libg.offset("_ZN21ToggleDebugMenuButton13buttonPressedEv")
            }
        }
    },
    offset(value) {
        return Module.findExportByName("libg.so", value);
    }
}

function InitUiButton(btnPtr, text) {
    let fileName = Libg.String.ctor(Memory.allocUtf8String("sc/ui.sc"));
    let scTextStr = Libg.String.ctor(Memory.allocUtf8String(text));

    let movieClip = Libg.StringTable.getMovieClip(fileName, scTextStr);
    Libg.CustomButton.setMovieClip(btnPtr, movieClip, 1);

    new NativeFunction(Libg.offset("_ZN13DisplayObject5setXYEff"), 'int', 
        ['pointer', 'float', 'float'])(btnPtr, 1300, 420);
    
    Libg.Stage.addChild(Libg.Stage.addr.instance.readPointer(), btnPtr);

    // new NativeFunction(Libg.offset("_ZN9TextField7setTextERK6String"), 'int', ['pointer', 'pointer'])(btnPtr, Libg.String.ctor(Memory.allocUtf8String("DEBUG"))); // IDK why but doesn't work
}

const Stage = {
    init() {
        var stage = Interceptor.attach(Libg.Stage.addr.ctor, {
            onEnter(args) {
                log("Stage::Stage() called");
                stage.detach();
                stage_address = args[0];
            }
        });
    }
}

function reloadGame() {
    new NativeFunction(Libg.offset("_ZN8GameMain10reloadGameEv"), 'int', ['pointer'])(Libg.offset("_ZN8GameMain12sm_pInstanceE").readPointer());
}

const LoadGame = {
    init() {
        var load = Interceptor.attach(Libg.GameMode.addr.addResourcesToLoad, {
            onEnter(args) {
                log("GameMode::addResourcesToLoad called");
                load.detach();
                Libg.ResourceListener.addFile(args[1], Memory.allocUtf8String("sc/debug.sc"));
                log("The sc/debug.sc has been loaded!");
            }
        });
    }
}


const GameLoaded = {
    init() {
        var gameLoaded = Interceptor.attach(Libg.MoneyHud.addr.ctor, {
            onEnter(args) {
                let opened = false;
                let debugMenuPtr;
                var hudUpdate;

                log("MoneyHUD::MoneyHUD() called");
                gameLoaded.detach();

                let dbgBtn = Libg.libc.malloc(300);
                Libg.MagicButton.ctor(dbgBtn);
                InitUiButton(dbgBtn, "debug_button");

                Interceptor.attach(Libg.offset("_ZN12CustomButton13buttonPressedEv"), {
                    onEnter(args) {
                        if (args[0].toInt32() == dbgBtn.toInt32()) {
                            log("Debug btn pressed!")
                            if (!opened) {
                                opened = true;
                                debugMenuPtr = Libg.libc.malloc(1000);
                                Libg.DebugMenu.DebugMenuCtor(debugMenuPtr);
                                Libg.Stage.addChild(Libg.Stage.addr.instance.readPointer(), debugMenuPtr);
                                log("DebugMenu is displayed");

                                hudUpdate = Interceptor.attach(Libg.HUD.addr.update, {
                                    onEnter(args) {
                                        Libg.DebugMenuBase.DebugMenuBaseUpdate(debugMenuPtr, 20);
                                    }
                                });

                                Interceptor.attach(Libg.ToggleDebugMenuButton.addr.buttonPressed, {
                                    onEnter(args) {
                                        opened = false;
                                        hudUpdate.detach();
                                        Libg.Stage.removeChild(Libg.Stage.addr.instance.readPointer(), debugMenuPtr);
                                        Libg.libc.free(debugMenuPtr);
                                    }
                                });
                            }
                            else {
                                opened = false;
                                hudUpdate.detach();
                                Libg.Stage.removeChild(Libg.Stage.addr.instance.readPointer(), debugMenuPtr);
                                Libg.libc.free(debugMenuPtr);
                            }
                        }
                    }
                })
            }
        });
    }
}


const HostPatcher = {
    init() {
        var connect = Interceptor.attach(Libg.libc.addr.getaddrinfo, {
            onEnter(args) {
                this.address = args[0].readUtf8String();
                log("Address: " + this.address);
                this.newAdress = args[0] = Memory.allocUtf8String("192.168.100.100"); //use your address
                log("New Address: " + this.newAdress.readUtf8String());
            }
        })
    }
}

rpc.exports.init = function() {
    try {
        Libg.init();
        Stage.init();
        LoadGame.init();
        GameLoaded.init();
        HostPatcher.init();
    } catch (ex) {
        log(ex.stack)
    }

    log("Initialized!");
}

function log(str) {
    console.log("[*] " + str);
}

String.prototype.ptr = function() {
    return Memory.allocUtf8String(this);
}

String.prototype.scptr = function() {
    return Libg.String.ctor(this.ptr())
}