//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <tss2/tss2_sys.h>

#include "tpm2_convert.h"
#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_openssl.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"


typedef struct tpm_quote_ctx tpm_quote_ctx;
struct tpm_quote_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    char *outFilePath;
    char *signature_path;
    char *message_path;
    char *pcr_path;
    FILE *pcr_output;
    tpm2_convert_sig_fmt sig_format;
    TPMI_ALG_HASH sig_hash_algorithm;
    tpm2_algorithm algs;
    TPM2B_DATA qualifyingData;
    TPML_PCR_SELECTION pcrSelections;
    TPMS_CAPABILITY_DATA cap_data;
    char *ak_auth_str;
    const char *context_arg;
    tpm2_loaded_object context_object;
    struct {
        UINT16 l : 1;
        UINT16 L : 1;
        UINT16 o : 1;
        UINT16 G : 1;
        UINT16 P : 1;
        UINT16 p : 1;
    } flags;
    tpm2_pcrs pcrs;
};

static tpm_quote_ctx ctx = {
    .auth = {
        .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    },
    .algs = {
        .count = 3,
        .alg = {
            TPM2_ALG_SHA1,
            TPM2_ALG_SHA256,
            TPM2_ALG_SHA384
        }
    },
    .qualifyingData = TPM2B_EMPTY_INIT,
};


// write all PCR banks according to g_pcrSelection & g_pcrs->
static bool write_pcr_values() {

    // PCR output to file wasn't requested
    if (ctx.pcr_output == NULL) {
        return true;
    }

    // Export TPML_PCR_SELECTION structure to pcr outfile
    if (fwrite(&ctx.pcrSelections,
            sizeof(TPML_PCR_SELECTION), 1,
            ctx.pcr_output) != 1) {
        LOG_ERR("write to output file failed: %s", strerror(errno));
        return false;
    }

    // Export PCR digests to pcr outfile
    if (fwrite(&ctx.pcrs.count, sizeof(UINT32), 1, ctx.pcr_output) != 1) {
        LOG_ERR("write to output file failed: %s", strerror(errno));
        return false;
    }

    UINT32 j;
    for (j = 0; j < ctx.pcrs.count; j++) {
        if (fwrite(&ctx.pcrs.pcr_values[j], sizeof(TPML_DIGEST), 1, ctx.pcr_output) != 1) {
            LOG_ERR("write to output file failed: %s", strerror(errno));
            return false;
        }
    }
    
    return true;
}

static bool write_output_files(TPM2B_ATTEST *quoted, TPMT_SIGNATURE *signature) {

    bool res = true;
    if (ctx.signature_path) {
        res &= tpm2_convert_sig_save(signature, ctx.sig_format, ctx.signature_path);
    }

    if (ctx.message_path) {
        res &= files_save_bytes_to_file(ctx.message_path,
                (UINT8*)quoted->attestationData,
                quoted->size);
    }

    res &= write_pcr_values();

    return res;
}

static bool quote(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE akHandle, TPML_PCR_SELECTION *pcrSelection)
{
    UINT32 rval;
    TPMT_SIG_SCHEME inScheme;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPM2B_ATTEST quoted = TPM2B_TYPE_INIT(TPM2B_ATTEST, attestationData);
    TPMT_SIGNATURE signature;
    TSS2L_SYS_AUTH_COMMAND cmd_auth_array = {
        1, {
            ctx.auth.session_data,
         },
    };

    if(!ctx.flags.G || !get_signature_scheme(sapi_context, akHandle, ctx.sig_hash_algorithm, &inScheme)) {
        inScheme.scheme = TPM2_ALG_NULL;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_Quote(sapi_context, akHandle, &cmd_auth_array,
            &ctx.qualifyingData, &inScheme, pcrSelection, &quoted,
            &signature, &sessionsDataOut));
    if(rval != TPM2_RC_SUCCESS)
    {
        LOG_PERR(Tss2_Sys_Quote, rval);
        return false;
    }

    tpm2_tool_output( "quoted: " );
    tpm2_util_print_tpm2b((TPM2B *)&quoted);
    tpm2_tool_output("\nsignature:\n" );
    tpm2_tool_output("  alg: %s\n", tpm2_alg_util_algtostr(signature.sigAlg, tpm2_alg_util_flags_sig));

    UINT16 size;
    BYTE *sig = tpm2_convert_sig(&size, &signature);
    tpm2_tool_output("  sig: ");
    tpm2_util_hexdump(sig, size);
    tpm2_tool_output("\n");
    free(sig);


    // Filter out invalid/unavailable PCR selections
    if (!pcr_check_pcr_selection(&ctx.cap_data, &ctx.pcrSelections)) {
        LOG_ERR("Failed to filter unavailable PCR values for quote!");
        return false;
    }

    // Gather PCR values from the TPM (the quote doesn't have them!)
    if (!pcr_read_pcr_values(sapi_context, &ctx.pcrSelections, &ctx.pcrs)) {
        LOG_ERR("Failed to retrieve PCR values related to quote!");
        return false;
    }

    // Grab the digest from the quote
    TPM2B_DIGEST quoteDigest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPM2B_DATA extraData = TPM2B_TYPE_INIT(TPM2B_DATA, buffer);
    if (!tpm2_util_get_digest_from_quote(&quoted, &quoteDigest, &extraData)) {
        LOG_ERR("Failed to get digest from quote!");
        return false;
    }

    // Print out PCR values as output
    if (!pcr_print_pcr_struct(&ctx.pcrSelections, &ctx.pcrs)) {
        LOG_ERR("Failed to print PCR values related to quote!");
        return false;
    }

    // Calculate the digest from our selected PCR values (to ensure correctness)
    TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    if (!tpm2_openssl_hash_pcr_banks(ctx.sig_hash_algorithm, &ctx.pcrSelections, &ctx.pcrs, &pcr_digest)) {
        LOG_ERR("Failed to hash PCR values related to quote!");
        return false;
    }
    tpm2_tool_output("calcDigest: ");
    tpm2_util_hexdump(pcr_digest.buffer, pcr_digest.size);
    tpm2_tool_output("\n");

    // Make sure digest from quote matches calculated PCR digest
    if (!tpm2_util_verify_digests(&quoteDigest, &pcr_digest)) {
        LOG_ERR("Error validating calculated PCR composite with quote");
        return false;
    }

    // Write everything out
    return write_output_files(&quoted, &signature);
}

static bool on_option(char key, char *value) {

    switch(key)
    {
    case 'C':
        ctx.context_arg = value;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.ak_auth_str = value;
        break;
    case 'l':
        if(!pcr_parse_list(value, strlen(value), &ctx.pcrSelections.pcrSelections[0]))
        {
            LOG_ERR("Could not parse pcr list, got: \"%s\"", value);
            return false;
        }
        ctx.flags.l = 1;
        break;
    case 'L':
        if(!pcr_parse_selections(value, &ctx.pcrSelections))
        {
            LOG_ERR("Could not parse pcr selections, got: \"%s\"", value);
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'o':
        ctx.outFilePath = value;
        ctx.flags.o = 1;
        break;
    case 'q':
        ctx.qualifyingData.size = sizeof(ctx.qualifyingData) - 2;
        if(tpm2_util_hex_to_byte_structure(value, &ctx.qualifyingData.size, ctx.qualifyingData.buffer) != 0)
        {
            LOG_ERR("Could not convert \"%s\" from a hex string to byte array!", value);
            return false;
        }
        break;
    case 's':
         ctx.signature_path = value;
         break;
    case 'm':
         ctx.message_path = value;
         break;
    case 'p':
         ctx.pcr_path = value;
         ctx.flags.p = 1;
         break;
    case 'f':
         ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(value);

         if (ctx.sig_format == signature_format_err) {
            return false;
         }
         break;
    case 'G':
        ctx.sig_hash_algorithm = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if(ctx.sig_hash_algorithm == TPM2_ALG_ERROR) {
            LOG_ERR("Could not convert signature hash algorithm selection, got: \"%s\"", value);
            return false;
        }
        ctx.flags.G = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "ak-context",           required_argument, NULL, 'C' },
        { "auth-ak",              required_argument, NULL, 'P' },
        { "id-list",              required_argument, NULL, 'l' },
        { "sel-list",             required_argument, NULL, 'L' },
        { "qualify-data",         required_argument, NULL, 'q' },
        { "signature",            required_argument, NULL, 's' },
        { "message",              required_argument, NULL, 'm' },
        { "pcrs",                 required_argument, NULL, 'p' },
        { "format",               required_argument, NULL, 'f' },
        { "sig-hash-algorithm",   required_argument, NULL, 'G' }
    };

    *opts = tpm2_options_new("C:P:l:L:q:s:m:p:f:G:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    /* TODO this whole file needs to be re-done, especially the option validation */
    if (!ctx.flags.l && !ctx.flags.L) {
        LOG_ERR("Expected either -l or -L to be specified.");
        return -1;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.ak_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid AK authorization, got\"%s\"", ctx.ak_auth_str);
            goto out;
        }
    }
    
    if (ctx.flags.p) {
        ctx.pcr_output = fopen(ctx.pcr_path, "wb+");
        if (!ctx.pcr_output) {
            LOG_ERR("Could not open PCR output file \"%s\" error: \"%s\"",
                    ctx.pcr_path, strerror(errno));
            goto out;
        }
    }

    result = tpm2_util_object_load(sapi_context, ctx.context_arg, &ctx.context_object);
    if (!result) {
        goto out;
    }

    result = pcr_get_banks(sapi_context, &ctx.cap_data, &ctx.algs);
    if (!result) {
        goto out;
    }

    result = quote(sapi_context, ctx.context_object.handle, &ctx.pcrSelections);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    if (ctx.pcr_output) {
        fclose(ctx.pcr_output);
    }

    result = tpm2_session_save(sapi_context, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_tool_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
