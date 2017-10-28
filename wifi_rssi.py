from scapy.all import *
from impacket import ImpactDecoder
import time
from collections import OrderedDict
import matplotlib.pyplot as plt
import threading

def parse_beacon(beacon):
    radio_packet = RTD.decode(str(beacon))
    _signal = radio_packet.get_dBm_ant_signal()
    if _signal:
        signal = _signal and -(256-_signal) or -120
    if signal >= -65:
        bssid = beacon[Dot11].addr2
        essid = beacon[Dot11Elt].info if beacon[Dot11Elt].info != '' else 'hidden essid'
        channel = ord(beacon[Dot11Elt][2].info)
        nowtime = time.time()-time_start
        asu = (113 + signal)/2
        if bssid not in exist_AP:
            count[0] += 1
            asu_list = [asu]
            time_list = [nowtime]
            exist_AP[bssid] = (essid,channel,count[0],asu_list,time_list)
        else:
            exist_AP[bssid][3].append(asu)
            exist_AP[bssid][4].append(nowtime)
    else:
        pass

def _sniff():
    sniff(iface='mon0', prn=parse_beacon, lfilter=lambda x:x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp))

def chart():
    plt.ion()
    plt.xlim(0,60)
    plt.ylim(15,50)
    colorlist = ['b','g','r','c','m','y','k']
    while True:
        for key in exist_AP.keys():
            x = exist_AP[key][4]
            y = exist_AP[key][3]
            selfcount = exist_AP[key][2]
            essid = exist_AP[key][0]
            if selfcount < 7:
                plt.plot(x, y, color=colorlist[selfcount], linewidth=1.0, linestyle='-', label=essid)
            elif selfcount < 14:
                plt.plot(x, y, color=colorlist[selfcount-7], linewidth=1.0, linestyle='--', label=essid)
            else:
                plt.plot(x, y, color=colorlist[selfcount-14], linewidth=1.0, linestyle='-.', label=essid)
        handles, labels = plt.gca().get_legend_handles_labels()
        by_label = OrderedDict(zip(labels, handles))
        plt.legend(by_label.values(), by_label.keys())
        plt.pause(0.1)

if __name__ == '__main__':
    exist_AP = {}
    count = [-1]
    RTD = ImpactDecoder.RadioTapDecoder()
    time_start = time.time()
    threading.Thread(target=_sniff).start()
    threading.Thread(target=chart).start()

