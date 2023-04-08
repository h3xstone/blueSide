#!/usr/bin/env python3

import psutil
from time import sleep
import json
import argparse
from hashlib import md5 as md5sum

class Monitor:
    def __init__(self, new, net, verb, log, act, blacklst, fopened, sigproc, sigfile, logsig, outsign):
        self.flag_new = new
        self.flag_net = net
        self.flag_verb = verb
        self.flag_log = log
        self.logs = {}      # out res
        self.act = act
        self.block = blacklst
        self.init_ps = psutil.pids()    # bluid init list of existing proc
        if self.act:
            self.act = self.act.lower()
        self.lst_action = []
        self.flag_fo = fopened
        self.flag_sigP = sigproc
        self.flag_sigF = sigfile
        self.flag_logSig = logsig
        self.logs_sig = []      # hash found
        self.lst_pidConnParsed = {}     # list {pid:[conn,conn..]} already logged
        self.fsout = outsign    # out file signature
        

    def getPsInfo(self,apid):
        try:
            dic_info = {}
            p = psutil.Process(apid)
            dic_info['name'] = p.name()
            try:
                dic_info['fullname'] = p.exe()
            except:
                dic_info['fullname'] = 'ERROR: not enough privileges!'
            try:
                dic_info['startedPath'] = p.cwd()
            except:
                dic_info['startedPath'] = 'ERROR: not enough privileges!'
            dic_info['cmdline'] = ' '.join(map(str,p.cmdline()))
            dic_info['privileges'] = p.username()
            dic_info['childs'] = [{'name':cp.name(),'pid': cp.pid} for cp in p.children(recursive=True)]
            if self.flag_fo:
                try:
                    of_lst = [fo.path for fo in p.open_files()]
                    if self.flag_sigF:
                        dic_info['fileOpen'] = []
                        for f in of_lst:
                            dic_info['fileOpen'].append({f:self.getFileHash(f,2)})                            
                    else:
                        dic_info['fileOpen'] = of_lst
                except:
                    pass
        except:
            pass
        return dic_info

    def doPsAction(self,pObj):
        p = pObj
        if p.is_running():
            print(f"! {self.act.upper()} {p.name()} - {p.pid} ... ",end="")
            if self.act == 'suspend':
                try:
                    p.suspend()
                    print("Done!")
                    # return a list with suspended and when ctrl+c in main
                    # ask for every ps what to do
                    self.lst_action.append({p.pid:p.name()})
                    self.init_ps.append(p.pid)
                except Exception as err:
                    print("Failed!\nERROR:",err)  
            elif self.act == 'terminate':
                try:
                    p.terminate()
                    print("Done!")
                    self.init_ps.append(p.pid)
                except Exception as err:
                    print("Failed!\nERROR:",err)
            elif self.act == 'kill':
                try:
                    p.kill()
                    print("Done!")
                    self.init_ps.append(p.pid)
                except Exception as err:
                    print("Failed!\nERROR:",err)        

    def getFileHash(self,target,atype):
        try:
            if atype == 1:
                p = psutil.Process(target)
                fd = p.exe()
            elif atype == 2:
                fd = target
            hash_md5 = md5sum()
            with open(fd, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_md5.update(chunk)
            h = hash_md5.hexdigest()
            return h
        except Exception as err:
            return "Access Denied"

    def startMon(self):
        ps_lst = psutil.pids()
        ps_diff = list(set(ps_lst) - set(self.init_ps))

        if len(ps_diff):
            # for every new process
            for p in ps_diff:
                lst_hash = []
                # case not options new/net
                if not self.flag_new and not self.flag_net and not self.act:
                    # add pid to init pid list otherwise is always detected as new
                    self.init_ps.append(p)
                
                if self.flag_verb:
                    ps_details = self.getPsInfo(p)
                    if self.flag_log:
                        if p in self.logs.keys():
                            self.logs[p].update({'details': ps_details})
                        else:
                            self.logs[p] = {'details': ps_details}
                
                # only option new -> print every new pid
                if self.flag_new and not self.flag_net:
                    print("+ New Process with PID:",p)
                    if self.flag_sigP:  
                        ph = self.getFileHash(p,1)
                        print("  Process hash (MD5):",ph)
                        # log process hash
                        if self.flag_logSig:
                            if 'Denied' not in ph:
                                lst_hash.append(ph)
                        if self.flag_log:
                            if p in self.logs.keys():
                                self.logs[p].update({'MD5': ph})
                            else:
                                self.logs[p] = {'MD5': ph}

                    if self.flag_verb:
                        print("  Details:")
                        for k,v in ps_details.items():
                            print(f"\t{k}: {v}")
                        # log files hash
                        if self.flag_logSig:
                            if 'fileOpen' in ps_details.keys():
                                if ps_details['fileOpen']:
                                    for el in ps_details['fileOpen']:
                                        v = ''.join([v for v in el.values() if isinstance(el,dict)])
                                        lst_hash.append(v)

                    # add pid to init pid list otherwise is print-repeated
                    self.init_ps.append(p)

                # only options net -> search connection
                if self.flag_net:
                    # if option net + new -> show all new pid + all pid with connection
                    # in this case add pid to list pid-conn because we want to see new conn generated by same pid
                    if self.flag_new and p not in self.lst_pidConnParsed.keys():
                        print("+ New Process with PID:",p)
                        if self.flag_sigP:
                            ph = self.getFileHash(p,1)
                            print("  Process hash (MD5):",ph)
                            # log ps hash
                            if self.flag_logSig:
                                if 'Denied' not in ph:
                                    lst_hash.append(ph)
                            if self.flag_log:
                                if p in self.logs.keys():
                                    self.logs[p].update({'MD5': ph})
                                else:
                                    self.logs[p] = {'MD5': ph}
                           
                        if self.flag_verb:
                            print("  Details:")
                            for k,v in ps_details.items():
                                print(f"\t{k}: {v}")
                            # log files hash
                            if self.flag_logSig:
                                if 'fileOpen' in ps_details.keys():
                                    if ps_details['fileOpen']:
                                        for el in ps_details['fileOpen']:
                                            v = ''.join([v for v in el.values() if isinstance(el,dict)])
                                            lst_hash.append(v)

                        self.lst_pidConnParsed[p] = []
                     
                    try:
                        conn = psutil.Process(p)
                        conn = conn.connections()   
                        if conn:
                            if p not in self.lst_pidConnParsed.keys():
                               # if option net + new not print pid because already printed
                                if self.flag_net and not self.flag_new:
                                    print("+ New Process with PID:",p)
                                    if self.flag_sigP:
                                        ph = self.getFileHash(p,1)
                                        print("  Process hash (MD5):",ph)
                                        # log ps hash
                                        if self.flag_logSig:
                                            if 'Denied' not in ph:
                                                lst_hash.append(ph)
                                        if self.flag_log:
                                            if p in self.logs.keys():
                                                self.logs[p].update({'MD5': ph})
                                            else:
                                                self.logs[p] = {'MD5': ph}
                                        
                                    if self.flag_verb:
                                        print("  Details:")
                                        for k,v in ps_details.items():
                                            print(f"\t{k}: {v}")
                                        # log files hash
                                        if self.flag_logSig:
                                            if 'fileOpen' in ps_details.keys():
                                                if ps_details['fileOpen']:
                                                    for el in ps_details['fileOpen']:
                                                        v = ''.join([v for v in el.values() if isinstance(el,dict)])
                                                        lst_hash.append(v)
                                                        
                                # add pid to list
                                self.lst_pidConnParsed[p] = []
                            
                            # if same pid same conn, skip
                            # PS. multiple requests same conn are not logged
                            if conn not in self.lst_pidConnParsed[p]:
                                print("  + New Connection:")
                                # case multiple conn
                                if isinstance(conn, list):
                                    for c in conn:
                                        (lip,lport) = c.laddr if c.laddr else (None,None)
                                        (rip,rport) = c.raddr if c.raddr else (None,None)

                                        # log = save res
                                        if self.flag_log:
                                            if 'connections' in self.logs[p].keys():
                                                self.logs[p]['connections'].append({'localIP':lip,'localPORT':lport,'remoteIP':rip,'remotePORT':rport})
                                            else:
                                                self.logs[p] = {'connections':[{'localIP':lip,'localPORT':lport,'remoteIP':rip,'remotePORT':rport}]}
                                        print(f"\tFrom: {lip}:{lport} => To: {rip}:{rport}")
                                        
                                        self.lst_pidConnParsed[p].append(conn)
                                else:
                                    (lip,lport) = conn.laddr if conn.laddr else (None,None)
                                    (rip,rport) = conn.raddr if conn.raddr else (None,None)
                                    if self.flag_log:
                                        if 'connections' in self.logs[p].keys():
                                            self.logs[p]['connections'].append({'localIP':lip,'localPORT':lport,'remoteIP':rip,'remotePORT':rport})
                                        else:
                                            self.logs[p] = {'connections':[{'localIP':lip,'localPORT':lport,'remoteIP':rip,'remotePORT':rport}]}
                                    print(f"\t\tFrom: {lip}:{lport} => To: {rip}:{rport}")
                                    
                                    self.lst_pidConnParsed[p].append(conn)
                               
                    except psutil.AccessDenied:
                        # no privilege
                        pass
                    except psutil.NoSuchProcess:
                        # pid closed
                        pass

                # check if must do action
                if self.act:
                    try:
                        pObj = psutil.Process(p)
                        pObjN = pObj.name()
                        if self.block:
                            if pObjN.lower() in self.block:
                                self.doPsAction(pObj)
                        else:
                            # block all proc
                            self.doPsAction(pObj)
                    except:
                        # pid lost
                        pass

                # write hashes to file
                if self.flag_logSig and lst_hash:
                    try:
                        print("+ Save files signatures to",self.fsout," ... ",end="")
                        with open(self.fsout, "a") as fd:
                            for h in lst_hash:
                                if h not in self.logs_sig:
                                    fd.write(h+'\n')
                        print("Done!")
                        # update list sign already written
                        self.logs_sig.extend(lst_hash)
                    except:
                        print("Failed!\nERROR: cannot write HASH signatures to file", self.fsout)
        
        ret_la = self.lst_action if self.lst_action else None
        ret_log = self.logs if self.logs else None
       
        return ret_la, ret_log
            
# action to do on suspended
def postPsAction(proc_list,typeAction, typeRec):
    for pel in proc_list:
        pp,pn = next(iter(pel.items()))
        try:
            p = psutil.Process(pp)
        except:
            # not found,closed
            pass
        if typeAction.lower() == 'resume':
            if typeRec == 2:
                ans = input(f"> resume {pp} ({pn}) ? (Y/n)  ")
                if ans.lower() == 'n':
                    continue
            print(f"+ Resume suspended {pp} ({pn}) ... ",end="")
            try:
                p.resume()
                print("Done!")
            except Exception as err:
                print("Failed!\nERROR:",err)
        elif typeAction.lower() == 'terminate':
            if typeRec == 2:
                ans = input(f"> terminate {pp} ({pn}) ? (Y/n)  ")
                if ans.lower() == 'n':
                    continue
            print(f"+ Terminate suspended {pp} ({pn}) ... ",end="")
            try:
                p.terminate()
                print("Done!")
            except Exception as err:
                print("Failed!\nERROR:",err)
        elif typeAction.lower() == 'kill':
            if typeRec == 2:
                ans = input(f"> kill {pp} ({pn}) ? (Y/n)  ")
                if ans.lower() == 'n':
                    continue
            print(f"+ Kill suspended {pp} ({pn}) ... ",end="")
            try:
                p.kill()
                print("Done!")
            except Exception as err:
                print("Failed!\nERROR:",err)


def main():
    desc = '''**************************************************************************************
* PSHUNTER is a tool designed to help in case of compromise (but can also be used    *
* to analyze the environment) with the ability to trace all new processes created    *
* and/or perform an action when a new process (or specific process name) is spawned. *
**************************************************************************************
    '''
    example = '''Example:
    pshunter.py -new                         // used for analysis, show/log all new process

    pshunter.py -new -net -v                 // used for analysis, show/log all new process detailed,
                                                in case process use network, show details of connections,
                                                no block action is done.

    pshunter.py -suspen                      // all new processes are automatically suspended
    
    pshunter.py -kill -block notepad.exe     // if a new process named "notepad.exe" is spawned
                                                it is automatically killed

    pshunter.py -t 0.2 -new -v -kill -block gnome-calculator
        // update every 200 milliseconds, show all new process with details (-v)
        // and if a process named "gnome-calculator" is launched kill it immediately

    pshunter.py -net -v -f -sigProc -sigFile -sigOut FWrules.txt -out logs.json
        // intercept only new processes that make network connections (-net),
        // for each process save details (-v) and calculate hash of itself (-sigProc),
        // log all files opened (-f) by process and create a signature of these (-sigFile),
        // as sooon as it has a hash, dump it in file (-sigOut Fwrules.txt),
        // when program stopped (CTRL+C) save logs into logs.json (-out)
    
PS.
    To stop/end tool press CTRL+C . If the "suspend" option has been used, when stopped tool
    will ask what to do with these suspended processes.
    '''
    parser = argparse.ArgumentParser(description=desc, epilog=example, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-new', default=False, action='store_true', help='log all new processes')
    parser.add_argument('-net', default=False, action='store_true', help='log only new processes that make network connection\n(used with option "-new" show all processes)')
    parser.add_argument('-suspend', default=False, action='store_true', help='action to do when intercept new process: suspend\nATTENTION: using this option without option "-block" will suspend every new process!')
    parser.add_argument('-term', default=False, action='store_true', help='action to do when intercept new process: terminate\nATTENTION: using this option without option "-block" will end every new process!')
    parser.add_argument('-kill', default=False, action='store_true', help='action to do when intercept new process: kill\nATTENTION: using this option without option "-block" will kill every new process!')
    parser.add_argument('-t', metavar='N', type=float, default='1', help='update time in seconds (default 1s). For ms use fraction like 0.2')
    parser.add_argument('-v', default=False, action='store_true', help='show details of each process intercepted. Must be used with options -new/-net')
    parser.add_argument('-block', metavar='ProcName1 ProcName2', nargs='+', help='blacklist of name of processes to block when intercepted, SPACE SEPARED\nThis option require an action (suspend/kill/term)')
    parser.add_argument('-f', default=False, action='store_true', help='log files opened by process')
    parser.add_argument('-sigProc', default=False, action='store_true', help='produce MD5 hash of process')
    parser.add_argument('-sigFile', default=False, action='store_true', help='produce MD5 hash of files opened by process\nMust be used with option "-f"')
    parser.add_argument('-sigOut', metavar="FWrules.txt", help='separed txt file where save MD5 hash (in case you want use DAC)')
    parser.add_argument('-out', metavar='result.json', help='save logs to json file')

    args = parser.parse_args()
    flag_new = args.new
    flag_net = args.net
    # actions
    flag_as = args.suspend
    flag_at = args.term
    flag_ak = args.kill
    if (flag_as and flag_at and flag_ak) or (flag_as and flag_at) or (flag_as and flag_ak) or (flag_at and flag_ak):
        print("Error: only 1 action allowed between suspend,terminate,kill")
        exit(0)
    if flag_as:
        flag_action = 'suspend'
    elif flag_at:
        flag_action = 'terminate'
    elif flag_ak:
        flag_action = 'kill'
    else:
        flag_action = None

    freq_up = args.t
    flag_verb = args.v
    if flag_verb and not (flag_net or flag_new):
        print("Error: option '-v' (verbose) must be used with '-net' and/or '-new'")
        exit(0)

    blst = [b.lower() for b in args.block] if args.block else None
    if blst and not flag_action:
        print("Error: block option must have a action type")
        exit(0)

    # out hash
    flag_f = args.f
    flag_sp = args.sigProc  
    flag_sf = args.sigFile  
    outSig = args.sigOut
    if outSig:
        flag_logSig = True
    else:
        flag_logSig = False
    if flag_sf and not flag_f:
        print("Error: option -sigFile must be used with option -f")
        exit(0)

    # out log
    outfd = args.out
    if outfd:
        flag_log = True
    else:
        flag_log = False
    
    if not flag_new and not flag_net and not flag_action and not flag_f and not flag_sp and not flag_sf and not blst and not flag_log and not flag_logSig:
        print("Error: no given options")
        exit(0)
    if flag_f and not flag_verb:
        print("Error: cannot log files opened (-f) without option verbose (-v)")
        exit(0)
    if flag_sf and not flag_verb:
        print("Error: cannot log files opened (-f) and their signatures (-sigFile) without option verbose (-v)")
        exit(0)

    # main
    flag = True
    print("[START]")
    obj = Monitor(flag_new, flag_net, flag_verb, flag_log, flag_action, blst, flag_f, flag_sp, flag_sf, flag_logSig, outSig)
    lst_action_done = []
    logs = {}
   
    try:
        while flag:
            lst_action_done, logs = obj.startMon()
            sleep(freq_up)        
    except KeyboardInterrupt:
        flag = False
        print("")
        if flag_log and logs:
            try:
                print("+ Save log data to",outfd," ... ",end="")
                with open(outfd,"w") as fd:
                    json.dump(logs, fd)
                print("Done!")
            except:
                print("Failed!\nERROR: cannot write logs to file",outfd)

    # show res
    if flag_action and lst_action_done is not None:
        print(f"LIST OF PROCESSES {flag_action.upper()}:")
        if flag_action == 'suspend':
            print(lst_action_done)
            print("\n>> What do you want do?\n1) resume\t2) terminate\t3) kill \t4) quit (leave suspended and exit prog)\n")
            while True:
                try:
                    ans = int(input("# "))
                    if ans == 1:
                        meth = 'resume'
                        break
                    elif ans == 2:
                        meth = 'terminate'
                        break
                    elif ans == 3:
                        meth = 'kill'
                        break
                    elif ans == 4:
                        break
                except:
                    pass
            if ans == 4:
                print("[END]")
                exit(0)
            print("\nSelect method:\n1) All\t2) Select manually\n")
            while True:
                try:
                    ans = int(input("# "))
                    if ans == 1:
                        meth2 = 1
                        break
                    elif ans == 2:
                        meth2 = 2
                        break
                except:
                    pass
            postPsAction(lst_action_done, meth, meth2)
    print("[END]")

if __name__ == '__main__':
    main()