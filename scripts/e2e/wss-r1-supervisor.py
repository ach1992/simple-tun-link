#!/usr/bin/python3
"""Disposable real-process supervisor used only inside STL R1 isolated namespaces."""
import os, sys, subprocess, signal, json, pathlib, time
store=pathlib.Path(os.environ["STL_R1_SIDE_ROOT"])/"runtime"
store.mkdir(mode=0o700,parents=True,exist_ok=True)
name=os.path.basename(sys.argv[0])
args=sys.argv[1:]
def proc_file(unit):
    if not unit.startswith("stl-wss-") or not unit.endswith(".service"):
        raise RuntimeError("Unexpected service identity")
    return store/(unit+".json")
def read(unit):
    f=proc_file(unit)
    if not f.is_file():return None
    return json.loads(f.read_text())
def active(pid):
    try:
        p=pathlib.Path("/proc")/str(pid)/"stat"
        v=p.read_text().split(") ")[1][0]
        return v not in "ZX"
    except Exception:return False
def launch(info):
    log=(store/(info["unit"]+".log")).open("ab")
    env=os.environ.copy();env.update(info["env"])
    p=subprocess.Popen(info["argv"],stdout=log,stderr=log,env=env,
                       stdin=subprocess.DEVNULL,start_new_session=True)
    info["pid"]=p.pid
    proc_file(info["unit"]).write_text(json.dumps(info))
    os.chmod(proc_file(info["unit"]),0o600)
def stop(info):
    if active(info["pid"]):
        try:os.kill(info["pid"],signal.SIGTERM)
        except ProcessLookupError:pass
        for _ in range(60):
            if not active(info["pid"]):break
            time.sleep(.025)
        if active(info["pid"]): raise RuntimeError("failed to stop WSS helper")
try:
    if name=="systemd-run":
        options=[];i=0
        while i<len(args) and args[i].startswith("--"):
            options.append(args[i]);i+=1
        cmd=args[i:]
        if not cmd or cmd[0]!="/usr/local/libexec/stl/wstunnel":
            raise RuntimeError("only approved WSS helper may start")
        unit=next(x[len("--unit="):] for x in options if x.startswith("--unit="))+".service"
        if read(unit):raise RuntimeError("WSS unit already exists")
        info={"unit":unit,"argv":cmd,
            "description":next(x[len("--description="):] for x in options if x.startswith("--description=")),
            "env":dict(x[len("--setenv="):].split("=",1) for x in options if x.startswith("--setenv=")),
            "pid":0,
            "properties":dict(x[len("--property="):].split("=",1)
                for x in options if x.startswith("--property=")),
            "collect":"--collect" in options}
        launch(info)
        kind=os.environ.get("STL_WSS_R2_AMBIGUOUS_TEST","")
        if kind=="helper-crash":
            os.kill(os.getppid(),signal.SIGKILL)
            sys.exit(1)
        if kind=="helper-cancel":
            os.kill(os.getppid(),signal.SIGINT)
            time.sleep(12)
            sys.exit(1)
        if kind=="helper-error":
            raise RuntimeError("injected post-launch systemd-run error")
        if kind=="helper-timeout":
            time.sleep(14)
            raise RuntimeError("injected late systemd-run response")
    elif name=="systemctl":
        if len(args)<2:raise RuntimeError("missing systemctl operation")
        op,unit=args[:2];info=read(unit)
        if op=="show":
            if not info:
                print("LoadState=not-found\nActiveState=inactive\nTransient=no\nDescription=\nExecStart=\nEnvironment=")
            else:
                print("LoadState=loaded")
                print("ActiveState="+("active" if active(info["pid"]) else "failed"))
                print("Transient=yes")
                print("Description="+info["description"])
                print("ExecStart={ path="+info["argv"][0]+" ; argv[]="+" ".join(info["argv"])+" ; }")
                print("Environment="+" ".join(k+"="+v for k,v in sorted(info["env"].items())))
                props=info["properties"]
                print("Type="+props["Type"])
                print("Restart="+props["Restart"])
                print("RestartUSec="+props["RestartSec"])
                for security in ("NoNewPrivileges","PrivateTmp","ProtectSystem","ProtectHome"):
                    print(security+"="+props[security])
                print("CollectMode="+("inactive-or-failed" if info["collect"] else "inactive"))
        elif op=="stop":
            if info:
                stop(info)
                # systemd transient --collect removes a stopped unit.
                proc_file(unit).unlink()
                if os.environ.get("STL_WSS_R2_REMOVE_CRASH_TEST","")=="stop":
                    os.kill(os.getppid(),signal.SIGKILL)
                    sys.exit(1)
        elif op=="restart":
            if not info:raise RuntimeError("Cannot restart missing WSS unit")
            stop(info);launch(info)
        else:raise RuntimeError("unsupported operation")
    else:raise RuntimeError("Not disposable systemd shim")
except Exception as e:
    print("isolated WSS supervisor: "+str(e),file=sys.stderr);sys.exit(1)
