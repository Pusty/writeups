from pwn import *
from pyroute2.netlink.nfnetlink.nftsocket import *
import dpkt
from pprint import pprint

policy = {NFT_MSG_NEWTABLE: nft_table_msg,
              NFT_MSG_GETTABLE: nft_table_msg,
              NFT_MSG_DELTABLE: nft_table_msg,
              NFT_MSG_NEWCHAIN: nft_chain_msg,
              NFT_MSG_GETCHAIN: nft_chain_msg,
              NFT_MSG_DELCHAIN: nft_chain_msg,
              NFT_MSG_NEWRULE: nft_rule_msg,
              NFT_MSG_GETRULE: nft_rule_msg,
              NFT_MSG_DELRULE: nft_rule_msg,
              NFT_MSG_NEWSET: nft_set_msg,
              NFT_MSG_GETSET: nft_set_msg,
              NFT_MSG_DELSET: nft_set_msg,
              NFT_MSG_NEWGEN: nft_gen_msg,
              NFT_MSG_GETGEN: nft_gen_msg,
              NFT_MSG_NEWSETELEM: nft_set_elem_list_msg,
              NFT_MSG_GETSETELEM: nft_set_elem_list_msg,
              NFT_MSG_DELSETELEM: nft_set_elem_list_msg,
              NFT_MSG_NEWFLOWTABLE: nft_flowtable_msg,
              NFT_MSG_GETFLOWTABLE: nft_flowtable_msg,
              NFT_MSG_DELFLOWTABLE: nft_flowtable_msg}

names = [i.split(" ")[7] for i in """  100     NFT_MSG_NEWTABLE,
  101     NFT_MSG_GETTABLE,
  102     NFT_MSG_DELTABLE,
  103     NFT_MSG_NEWCHAIN,
  104     NFT_MSG_GETCHAIN,
  105     NFT_MSG_DELCHAIN,
  106     NFT_MSG_NEWRULE,
  107     NFT_MSG_GETRULE,
  108     NFT_MSG_DELRULE,
  109     NFT_MSG_NEWSET,
  110     NFT_MSG_GETSET,
  111     NFT_MSG_DELSET,
  112     NFT_MSG_NEWSETELEM,
  113     NFT_MSG_GETSETELEM,
  114     NFT_MSG_DELSETELEM,
  115     NFT_MSG_NEWGEN,
  116     NFT_MSG_GETGEN,
  117     NFT_MSG_TRACE,
  118     NFT_MSG_NEWOBJ,
  119     NFT_MSG_GETOBJ,
  120     NFT_MSG_DELOBJ,
  121     NFT_MSG_GETOBJ_RESET,
  122     NFT_MSG_NEWFLOWTABLE,
  123     NFT_MSG_GETFLOWTABLE,
  124     NFT_MSG_DELFLOWTABLE,
  125     NFT_MSG_MAX""".split("\n")]
#for timestamp, buf in dpkt.pcap.Reader(open("./nft/task/easynft.pcap", "rb")):
for timestamp, buf in dpkt.pcap.Reader(open("./nft.pcap", "rb")):
    bufcopy = buf[16:]
    typ = u16(bufcopy[4:6])
    if typ == 3:
        print("END OF MULTIPART")
        pass
    elif (typ&0xff) in policy:
        print(f"TYPE: {names[typ & 0xff]}")
        while len(bufcopy) > 0:
            x = policy[typ & 0xff](bufcopy)
            x.decode()
            pprint(x)
            bufcopy = bufcopy[x["header"]["length"]:]
    else:
        print(bufcopy)
        pass

    print("-"*80)