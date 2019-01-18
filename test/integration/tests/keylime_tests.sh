#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

source helpers.sh

#TODO: Get rid of PATH mods
PATH="$PATH:/home/test/Downloads/repos/tpm2-tools/tools/"

handle_ek=0x81010009
handle_ak=0x8101000a
handle_nv=0x1500018
handle_hier=0x40000001
ek_alg=rsa
ak_alg=rsa
digestAlg=sha256
signAlg=rsassa
ownerpw=ownerpass
endorsepw=endorsepass
ekpw=ekpass
akpw=akpass

file_input_data=secret.data
file_input_key=nv.data
output_ek_pub_pem=ekpub.pem
output_ek_pub=ek.pub
output_ak_pub_pem=akpub.pem
output_ak_pub=ak.pub
output_ak_pub_name=ak.name
output_mkcredential=mkcred.out
output_actcredential=actcred.out
output_quote=quote.out
output_quotesig=quotesig.out
output_quotepcr=quotepcr.out

cleanup() {
  rm -f $file_input_data $file_input_key $output_ek_pub $output_ek_pub_pem $output_ak_pub \
        $output_ak_pub_pem $output_ak_pub_name $output_mkcredential \
        $output_actcredential $output_quote $output_quotesig $output_quotepcr rand.out 

  tpm2_pcrreset 16
  tpm2_evictcontrol -a o -c $handle_ek -P "$ownerpw" 2>/dev/null || true
  tpm2_evictcontrol -a o -c $handle_ak -P "$ownerpw" 2>/dev/null || true

  tpm2_nvrelease -x $handle_nv -a $handle_hier -P "$ownerpw" 2>/dev/null || true

  tpm2_changeauth -O "$ownerpw" -E "$endorsepw" 2>/dev/null || true

  ina "$@" "no-shut-down"
  if [ $? -ne 0 ]; then
    #TODO: do a real shutdown
    #shut_down
    echo "shutdown"
  fi
}
trap cleanup EXIT

#TODO: do a real startup
#start_up
switch_to_test_dir

cleanup "no-shut-down"

tpm2_changeauth -o "$ownerpw" -e "$endorsepw"
echo "12345678" > $file_input_data
echo "1234567890123456789012345678901" > $file_input_key

getrandom() {
  tpm2_getrandom -o rand.out $1
  local file_size=`stat --printf="%s" rand.out`
  loaded_randomness=`cat rand.out | xxd -p -c $file_size`
}

# Key generation
tpm2_createek -c $handle_ek -G $ek_alg -p $output_ek_pub_pem -f pem -P "$ekpw" -o "$ownerpw" -e "$endorsepw"
tpm2_readpublic -c $handle_ek -o $output_ek_pub

tpm2_createak -C $handle_ek -k $handle_ak -G $ak_alg -D $digestAlg -s $signAlg -p $output_ak_pub_pem -f pem -n $output_ak_pub_name  -e "$endorsepw" -P "$akpw" -o "$ownerpw"
tpm2_readpublic -c $handle_ak -o $output_ak_pub


# Validate keys (registrar)
file_size=`stat --printf="%s" $output_ak_pub_name`
loaded_key_name=`cat $output_ak_pub_name | xxd -p -c $file_size`
tpm2_makecredential -e $output_ek_pub -s $file_input_data -n $loaded_key_name -o $output_mkcredential --no-tpm
tpm2_activatecredential -c $handle_ak -C $handle_ek -f $output_mkcredential -o $output_actcredential -P "$akpw" -E "$endorsepw"
diff $file_input_data $output_actcredential


# Quoting
tpm2_pcrreset 16
tpm2_pcrextend 16:sha256=6ea40aa7267bb71251c1de1c3605a3df759b86b22fa9f62aa298d4197cd88a38
tpm2_pcrlist
getrandom 20
tpm2_deluxequote -C $handle_ak -L $digestAlg:15,16,22 -q $loaded_randomness -m $output_quote -s $output_quotesig -p $output_quotepcr -G $digestAlg -P "$akpw"


# Verify quote
tpm2_checkquote -c $output_ak_pub_pem -m $output_quote -s $output_quotesig -p $output_quotepcr -G $digestAlg -q $loaded_randomness


# Save U key from verifier
tpm2_nvdefine -x $handle_nv -a $handle_hier -s 32 -t "ownerread|policywrite|ownerwrite" -p "indexpass" -P "$ownerpw"
tpm2_nvwrite -x $handle_nv -a $handle_hier -P "$ownerpw" $file_input_key
tpm2_nvread -x $handle_nv -a $handle_hier -s 32 -P "$ownerpw"

exit 0

