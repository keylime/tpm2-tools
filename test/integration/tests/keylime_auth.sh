#!/bin/bash

rm session.ctx secret.policy prim.ctx key.* plain.txt encrypt.out

TPM_RH_OWNER=0x40000001
TPM_RH_ENDORSEMENT=0x4000000B
handle_ek=0x81010009
handle_ak=0x8101000a

tpm2_startup -c
tpm2_changeauth -o "ownerpw" -e "endorsepw"
echo "SECRET DATA" > plain.txt



echo "CREATE POLICY"
tpm2_startauthsession -S session.ctx
tpm2_policypassword -S session.ctx -o secret.policy 
tpm2_flushcontext -S session.ctx

echo "MAKE OBJECTS WITH POLICY"
tpm2_createprimary -a o -g sha256 -G rsa -o prim.ctx -P "ownerpw"
tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C prim.ctx -L secret.policy -p "objpass"
tpm2_load -C prim.ctx -u key.pub -r key.priv -n key.name -o key.ctx

echo "REVEAL SECRET"
tpm2_startauthsession -a -S session.ctx
tpm2_policypassword -S session.ctx -o secret.policy 
tpm2_encryptdecrypt -c key.ctx -o encrypt.out -I plain.txt -p "session:session.ctx+objpass"
tpm2_encryptdecrypt -c key.ctx -D -I encrypt.out -p "session:session.ctx+objpass"
tpm2_flushcontext -S session.ctx


rm session.ctx secret.policy prim.ctx key.* encrypt.out


echo
echo "=================================================="
echo


tpm2_changeauth -O "ownerpw" -E "endorsepw"

echo "CREATE SECRET POLICY"
tpm2_startauthsession -S session.ctx
tpm2_policysecret -S session.ctx -c $TPM_RH_ENDORSEMENT -o secret.policy 
tpm2_flushcontext -S session.ctx

echo "MAKE ENDORSE OBJECTS WITH POLICY?"
tpm2_createek -c $handle_ek -G rsa -p key.pub -f pem
tpm2_createak -C $handle_ek -k $handle_ak -G rsa -D sha256 -s rsassa -p key2.pub -f pem -n key2.name
tpm2_deluxequote -C $handle_ak -L sha256:15,16,22

echo "MAKE OBJECTS WITH POLICY"
tpm2_createprimary -a o -g sha256 -G rsa -o prim.ctx #-P "ownerpw"
tpm2_create -g sha256 -u key.pub -r key.priv -I plain.txt -C prim.ctx -L secret.policy
tpm2_load -C prim.ctx -u key.pub -r key.priv -n key.name -o key.ctx

echo "REVEAL SECRET"
tpm2_startauthsession -a -S session.ctx
tpm2_policysecret -S session.ctx -c $TPM_RH_ENDORSEMENT -o secret.policy 
tpm2_unseal -p "session:session.ctx" -c key.ctx
tpm2_flushcontext -S session.ctx



#tpm2_changeauth -O "ownerpw" -E "endorsepw"

tpm2_evictcontrol -a o -c $handle_ek
tpm2_evictcontrol -a o -c $handle_ak
rm session.ctx secret.policy prim.ctx key.* key2.* plain.txt


