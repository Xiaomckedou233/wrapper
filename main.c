#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "import.h"
#include "cmdline.h"
#include "cjson/cjson.h"
#ifndef MyRelease
#include "subhook/subhook.c"
#include "subhook/subhook.h"
#endif

static struct shared_ptr apInf;
static uint8_t leaseMgr[16];
static struct shared_ptr reqCtx;
struct gengetopt_args_info args_info;
char *amUsername, *amPassword;
struct shared_ptr GUID;
int decryptCount = 1000;
int offlineFlag;
char *device_infos[9];

// Account info cache
static char *g_storefront_id = NULL;
static char *g_dev_token = NULL;
static char *g_music_token = NULL;

// API Globals
pthread_mutex_t api_mutex = PTHREAD_MUTEX_INITIALIZER;
static char *g_req_music_token = NULL;
static char *g_req_storefront_id = NULL;

struct curl_slist {
    char *data;
    struct curl_slist *next;
};

struct curl_slist *slist_append(struct curl_slist *list, const char *string) {
    struct curl_slist *new_item = malloc(sizeof(struct curl_slist));
    new_item->next = NULL;
    new_item->data = strdup(string);
    
    if (!list) return new_item;
    
    struct curl_slist *ptr = list;
    while (ptr->next) ptr = ptr->next;
    ptr->next = new_item;
    return list;
}

void slist_free_all(struct curl_slist *list) {
    struct curl_slist *ptr = list;
    while (ptr) {
        struct curl_slist *next = ptr->next;
        free(ptr->data);
        free(ptr);
        ptr = next;
    }
}

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < (3 - input_length % 3) % 3; i++)
        encoded_data[*output_length - 1 - i] = '=';

    encoded_data[*output_length] = '\0';
    return encoded_data;
}

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {
    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    int decoding_table[256];
    for (int i = 0; i < 256; i++) decoding_table[i] = -1;
    for (int i = 0; i < 64; i++) decoding_table[(unsigned char)base64_table[i]] = i;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(unsigned char)data[i++]];

        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

#ifndef MyRelease
int32_t CURLOPT_SSL_VERIFYPEER = 64;
int32_t CURLOPT_SSL_VERIFYHOST = 81;
int32_t CURLOPT_PINNEDPUBLICKEY = 10230;

subhook_t curl_hook;
subhook_t curl_perform_hook;
struct curl_slist *g_injected_headers = NULL;

void *curl_easy_perform_hook(void *curl) {
    subhook_remove(curl_perform_hook);
    void *ret = curl_easy_perform(curl);
    subhook_install(curl_perform_hook);
    
    if (g_injected_headers) {
        slist_free_all(g_injected_headers);
        g_injected_headers = NULL;
    }
    return ret;
}

void curl_easy_setopt_hook(void *curl, int32_t option, ...) {
    va_list args;
    va_start(args, option);
    void* param = va_arg(args, void*);
    
    subhook_remove(curl_hook);
 
    if (option == CURLOPT_SSL_VERIFYPEER || 
        option == CURLOPT_SSL_VERIFYHOST || 
        option == CURLOPT_PINNEDPUBLICKEY) {
        curl_easy_setopt(curl, option, 0L);
        // printf("[+] hooked curl_easy_setopt %d\n", option);
    } else if (option == 10023) { // CURLOPT_HTTPHEADER
        struct curl_slist *list = (struct curl_slist *)param;
        if (g_req_music_token) {
             struct curl_slist *new_list = NULL;
             struct curl_slist *ptr = list;
             while (ptr) {
                 new_list = slist_append(new_list, ptr->data);
                 ptr = ptr->next;
             }
             
             char buf[1024];
             snprintf(buf, sizeof(buf), "media-user-token: %s", g_req_music_token);
             new_list = slist_append(new_list, buf);
             
             if (g_req_storefront_id) {
                 snprintf(buf, sizeof(buf), "X-Apple-Store-Front: %s", g_req_storefront_id);
                 new_list = slist_append(new_list, buf);
             }
             
             if (g_injected_headers) {
                 slist_free_all(g_injected_headers);
             }
             g_injected_headers = new_list;
             curl_easy_setopt(curl, option, new_list);
        } else {
            curl_easy_setopt(curl, option, param);
        }
    } else {
        curl_easy_setopt(curl, option, param);
    }
 
    va_end(args);
    subhook_install(curl_hook);
}

int android_log_print_hook(int prio, const char *tag, const char *fmt, ...) {
    char log_buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(log_buffer, sizeof(log_buffer), fmt, args);
    va_end(args);
    printf("[%s] %s\n", tag, log_buffer);
    return 0;
}

int android_log_write_hook(int prio, const char *tag, const char *text) {
    printf("[%s] %s\n", tag, text);
    return 0;
}

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
#endif

int file_exists(char *filename) {
  struct stat buffer;   
  return (stat (filename, &buffer) == 0);
}

char *strcat_b(char *dest, char* src) {
    size_t len1 = strlen(dest);
    size_t len2 = strlen(src);

    char *result = malloc(len1 + len2 + 1);
    if (!result) return NULL; 

    strcpy(result, dest);
    strcat(result, src);

    return result;
}

int split_string_safe(const char *str, const char *delim, char **components, 
                      int max_components, char **out_copy_to_free) 
{
    *out_copy_to_free = NULL;

    char *copy = strdup(str);
    if (copy == NULL) {
        return -1; 
    }

    *out_copy_to_free = copy;

    int count = 0;
    char *saveptr;
    char *token;

    token = strtok_r(copy, delim, &saveptr);

    while (token != NULL && count < max_components) {
        components[count] = token;
        count++;
        token = strtok_r(NULL, delim, &saveptr);
    }

    return count;
}

static void dialogHandler(long j, struct shared_ptr *protoDialogPtr,
                          struct shared_ptr *respHandler) {
    const char *const title = std_string_data(
        _ZNK17storeservicescore14ProtocolDialog5titleEv(protoDialogPtr->obj));
    fprintf(stderr, "[.] dialogHandler: {title: %s, message: %s}\n", title,
            std_string_data(_ZNK17storeservicescore14ProtocolDialog7messageEv(
                protoDialogPtr->obj)));

    unsigned char ptr[72];
    memset(ptr + 8, 0, 16);
    *(void **)(ptr) =
        &_ZTVNSt6__ndk120__shared_ptr_emplaceIN17storeservicescore22ProtocolDialogResponseENS_9allocatorIS2_EEEE +
        2;
    struct shared_ptr diagResp = {.obj = ptr + 24, .ctrl_blk = ptr};
    _ZN17storeservicescore22ProtocolDialogResponseC1Ev(diagResp.obj);

    struct std_vector *butVec =
        _ZNK17storeservicescore14ProtocolDialog7buttonsEv(protoDialogPtr->obj);
    if (strcmp("Sign In", title) == 0) {
        for (struct shared_ptr *b = butVec->begin; b != butVec->end; ++b) {
            if (strcmp("Use Existing Apple ID",
                       std_string_data(
                           _ZNK17storeservicescore14ProtocolButton5titleEv(
                               b->obj))) == 0) {
                _ZN17storeservicescore22ProtocolDialogResponse17setSelectedButtonERKNSt6__ndk110shared_ptrINS_14ProtocolButtonEEE(
                    diagResp.obj, b);
                break;
            }
        }
    } else {
        for (struct shared_ptr *b = butVec->begin; b != butVec->end; ++b) {
            fprintf(
                stderr, "[.] button %p: %s\n", b->obj,
                std_string_data(
                    _ZNK17storeservicescore14ProtocolButton5titleEv(b->obj)));
        }
    }
    _ZN20androidstoreservices28AndroidPresentationInterface28handleProtocolDialogResponseERKlRKNSt6__ndk110shared_ptrIN17storeservicescore22ProtocolDialogResponseEEE(
        apInf.obj, &j, &diagResp);
}

static void credentialHandler(struct shared_ptr *credReqHandler,
                              struct shared_ptr *credRespHandler) {
    const uint8_t need2FA =
        _ZNK17storeservicescore18CredentialsRequest28requiresHSA2VerificationCodeEv(
            credReqHandler->obj);
    fprintf(
        stderr, "[.] credentialHandler: {title: %s, message: %s, 2FA: %s}\n",
        std_string_data(_ZNK17storeservicescore18CredentialsRequest5titleEv(
            credReqHandler->obj)),
        std_string_data(_ZNK17storeservicescore18CredentialsRequest7messageEv(
            credReqHandler->obj)),
        need2FA ? "true" : "false");

    int passLen = strlen(amPassword);

    if (need2FA) {
        if (args_info.code_from_file_flag) {
            fprintf(stderr, "[!] Enter your 2FA code into rootfs/%s/2fa.txt\n", args_info.base_dir_arg);
            fprintf(stderr, "[!] Example command: echo -n 114514 > rootfs/%s/2fa.txt\n", args_info.base_dir_arg);
            fprintf(stderr, "[!] Waiting for input...\n");
            int count = 0;
            while (1)
            {
                if (count >= 20) {
                    fprintf(stderr, "[!] Failed to get 2FA Code in 60s. Exiting...\n");
                    exit(0);
                }
                char *path = strcat_b(args_info.base_dir_arg, "/2fa.txt");
                if (file_exists(path)) {
                    FILE *fp = fopen(path, "r");
                    fscanf(fp, "%6s", amPassword + passLen);
                    remove(path);
                    fprintf(stderr, "[!] Code file detected! Logging in...\n");
                    break;
                } else {
                    sleep(3);
                    count++;
                }
            }
        } else {
            printf("2FA code: ");
            scanf("%6s", amPassword + passLen);
        }
    }

    uint8_t *const ptr = malloc(80);
    memset(ptr + 8, 0, 16);
    *(void **)(ptr) =
        &_ZTVNSt6__ndk120__shared_ptr_emplaceIN17storeservicescore19CredentialsResponseENS_9allocatorIS2_EEEE +
        2;
    struct shared_ptr credResp = {.obj = ptr + 24, .ctrl_blk = ptr};
    _ZN17storeservicescore19CredentialsResponseC1Ev(credResp.obj);

    union std_string username = new_std_string(amUsername);
    _ZN17storeservicescore19CredentialsResponse11setUserNameERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        credResp.obj, &username);

    union std_string password = new_std_string(amPassword);
    _ZN17storeservicescore19CredentialsResponse11setPasswordERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        credResp.obj, &password);

    _ZN17storeservicescore19CredentialsResponse15setResponseTypeENS0_12ResponseTypeE(
        credResp.obj, 2);

    _ZN20androidstoreservices28AndroidPresentationInterface25handleCredentialsResponseERKNSt6__ndk110shared_ptrIN17storeservicescore19CredentialsResponseEEE(
        apInf.obj, &credResp);
}

#ifndef MyRelease
static uint8_t allDebug() { return 1; }
#endif

static inline void init() {
    // srand(time(0));

    // raise(SIGSTOP);
    fprintf(stderr, "[+] starting...\n");
    setenv("ANDROID_DNS_MODE", "local", 1);
    if (args_info.proxy_given) {
        fprintf(stderr, "[+] Using proxy %s\n", args_info.proxy_arg);
        setenv("all_proxy", args_info.proxy_arg, 1);
    }

    static const char *resolvers[2] = {"223.5.5.5", "223.6.6.6"};
    _resolv_set_nameservers_for_net(0, resolvers, 2, ".");

    // static char android_id[16];
    // for (int i = 0; i < 16; ++i) {
    //     android_id[i] = "0123456789abcdef"[rand() % 16];
    // }
    union std_string conf1 = new_std_string(device_infos[8]);
    union std_string conf2 = new_std_string("");
    _ZN14FootHillConfig6configERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE(
        &conf1);

    // union std_string root = new_std_string("/");
    // union std_string natLib = new_std_string("/system/lib64/");
    // void *foothill = malloc(120);
    // _ZN8FootHillC2ERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEES8_(
    //     foothill, &root, &natLib);
    // _ZN8FootHill24defaultContextIdentifierEv(foothill);

    _ZN17storeservicescore10DeviceGUID8instanceEv(&GUID);

    static uint8_t ret[88];
    static unsigned int conf3 = 29;
    static uint8_t conf4 = 1;
    _ZN17storeservicescore10DeviceGUID9configureERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_RKjRKb(
        &ret, GUID.obj, &conf1, &conf2, &conf3, &conf4);
}

static inline struct shared_ptr init_ctx() {
    fprintf(stderr, "[+] initializing ctx...\n");
    union std_string strBuf =
        new_std_string(strcat_b(args_info.base_dir_arg, "/mpl_db"));

    struct shared_ptr reqCtx;
    _ZNSt6__ndk110shared_ptrIN17storeservicescore14RequestContextEE11make_sharedIJRNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEEES3_DpOT_(
        &reqCtx, &strBuf);

    static uint8_t ptr[480];
    *(void **)(ptr) =
        &_ZTVNSt6__ndk120__shared_ptr_emplaceIN17storeservicescore20RequestContextConfigENS_9allocatorIS2_EEEE +
        2;
    struct shared_ptr reqCtxCfg = {.obj = ptr + 32, .ctrl_blk = ptr};

    _ZN17storeservicescore20RequestContextConfigC2Ev(reqCtxCfg.obj);
	// _ZN17storeservicescore20RequestContextConfig9setCPFlagEb(reqCtx.obj, 1);
    _ZN17storeservicescore20RequestContextConfig20setBaseDirectoryPathERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtxCfg.obj, &strBuf);
    strBuf = new_std_string(device_infos[0]);
    _ZN17storeservicescore20RequestContextConfig19setClientIdentifierERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtxCfg.obj, &strBuf);
    strBuf = new_std_string(device_infos[1]);
    _ZN17storeservicescore20RequestContextConfig20setVersionIdentifierERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtxCfg.obj, &strBuf);
    strBuf = new_std_string(device_infos[2]);
    _ZN17storeservicescore20RequestContextConfig21setPlatformIdentifierERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtxCfg.obj, &strBuf);
    strBuf = new_std_string(device_infos[3]);
    _ZN17storeservicescore20RequestContextConfig17setProductVersionERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtxCfg.obj, &strBuf);
    strBuf = new_std_string(device_infos[4]);
    _ZN17storeservicescore20RequestContextConfig14setDeviceModelERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtxCfg.obj, &strBuf);
    strBuf = new_std_string(device_infos[5]);
    _ZN17storeservicescore20RequestContextConfig15setBuildVersionERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtxCfg.obj, &strBuf);
    strBuf = new_std_string(device_infos[6]);
    _ZN17storeservicescore20RequestContextConfig19setLocaleIdentifierERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtxCfg.obj, &strBuf);
    strBuf = new_std_string(device_infos[7]);
    _ZN17storeservicescore20RequestContextConfig21setLanguageIdentifierERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtxCfg.obj, &strBuf);

    _ZN21RequestContextManager9configureERKNSt6__ndk110shared_ptrIN17storeservicescore14RequestContextEEE(
        &reqCtx);
    static uint8_t buf[88];
    _ZN17storeservicescore14RequestContext4initERKNSt6__ndk110shared_ptrINS_20RequestContextConfigEEE(
        &buf, reqCtx.obj, &reqCtxCfg);
    strBuf = new_std_string(args_info.base_dir_arg);
    _ZN17storeservicescore14RequestContext24setFairPlayDirectoryPathERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(
        reqCtx.obj, &strBuf);

    _ZNSt6__ndk110shared_ptrIN20androidstoreservices28AndroidPresentationInterfaceEE11make_sharedIJEEES3_DpOT_(
        &apInf);

    _ZN20androidstoreservices28AndroidPresentationInterface16setDialogHandlerEPFvlNSt6__ndk110shared_ptrIN17storeservicescore14ProtocolDialogEEENS2_INS_36AndroidProtocolDialogResponseHandlerEEEE(
        apInf.obj, &dialogHandler);

    _ZN20androidstoreservices28AndroidPresentationInterface21setCredentialsHandlerEPFvNSt6__ndk110shared_ptrIN17storeservicescore18CredentialsRequestEEENS2_INS_33AndroidCredentialsResponseHandlerEEEE(
        apInf.obj, &credentialHandler);

    _ZN17storeservicescore14RequestContext24setPresentationInterfaceERKNSt6__ndk110shared_ptrINS_21PresentationInterfaceEEE(
        reqCtx.obj, &apInf);

    return reqCtx;
}

extern void *endLeaseCallback;
extern void *pbErrCallback;

static inline void writefull(const int connfd, void *const buf,
                             const size_t size) {
    size_t red = 0;
    while (size > red) {
        const ssize_t b = write(connfd, ((uint8_t *)buf) + red, size - red);
        if (b <= 0) {
            perror("write");
            break;
        }
        red += b;
    }
}

static void *FHinstance = NULL;
static void *preshareCtx = NULL;

inline static void *getKdContext(const char *const adam,
                                 const char *const uri) {
    uint8_t isPreshare = (strcmp("0", adam) == 0);
    if (isPreshare && preshareCtx != NULL) {
        return preshareCtx;
    }
    fprintf(stderr, "[.] adamId: %s, uri: %s\n", adam, uri);

    union std_string defaultId = new_std_string(adam);
    union std_string keyUri = new_std_string(uri);
    union std_string keyFormat =
        new_std_string("com.apple.streamingkeydelivery");
    union std_string keyFormatVer = new_std_string("1");
    union std_string serverUri = new_std_string(
        "https://play.itunes.apple.com/WebObjects/MZPlay.woa/music/fps");
    union std_string protocolType = new_std_string("simplified");
    union std_string fpsCert = new_std_string(fairplayCert);

    struct shared_ptr persistK = {.obj = NULL};
    _ZN21SVFootHillSessionCtrl16getPersistentKeyERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEES8_S8_S8_S8_S8_S8_S8_(
        &persistK, FHinstance, &defaultId, &defaultId, &keyUri, &keyFormat,
        &keyFormatVer, &serverUri, &protocolType, &fpsCert);

    if (persistK.obj == NULL)
        return NULL;

    struct shared_ptr SVFootHillPContext;
    _ZN21SVFootHillSessionCtrl14decryptContextERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEERKN11SVDecryptor15SVDecryptorTypeERKb(
        &SVFootHillPContext, FHinstance, persistK.obj);

    if (SVFootHillPContext.obj == NULL)
        return NULL;

    void *kdContext =
        *_ZNK18SVFootHillPContext9kdContextEv(SVFootHillPContext.obj);
    if (kdContext != NULL && isPreshare)
        preshareCtx = kdContext;
    return kdContext;
}

void refresh_decrypt_ctx() {
    uint8_t autom = 1;
    _ZN22SVPlaybackLeaseManager12requestLeaseERKb(leaseMgr, &autom);
    _ZN21SVFootHillSessionCtrl16resetAllContextsEv(FHinstance);
    preshareCtx = NULL;
    preshareCtx = getKdContext("0", "skd://itunes.apple.com/P000000000/s1/e1");
    printf("[!] refreshed context\n");
}

void handle(const int connfd) {
    char buffer[4096];
    ssize_t n = read(connfd, buffer, sizeof(buffer) - 1);
    if (n <= 0) return;
    buffer[n] = '\0';

    // Check for POST
    if (strncmp(buffer, "POST", 4) != 0) {
        const char *resp = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
        return;
    }

    // Find body
    char *body = strstr(buffer, "\r\n\r\n");
    if (!body) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
        return;
    }
    body += 4;

    cJSON *json = cJSON_Parse(body);
    if (!json) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
        return;
    }

    cJSON *adamIdItem = cJSON_GetObjectItemCaseSensitive(json, "adamId");
    cJSON *uriItem = cJSON_GetObjectItemCaseSensitive(json, "uri");
    cJSON *tokenItem = cJSON_GetObjectItemCaseSensitive(json, "token");
    cJSON *storefrontItem = cJSON_GetObjectItemCaseSensitive(json, "storefront");
    cJSON *dataItem = cJSON_GetObjectItemCaseSensitive(json, "data");

    if (!cJSON_IsString(adamIdItem) || !cJSON_IsString(uriItem) || !cJSON_IsString(tokenItem) || !cJSON_IsString(dataItem)) {
        cJSON_Delete(json);
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
        return;
    }

    size_t sample_size = 0;
    unsigned char *sample = base64_decode(dataItem->valuestring, strlen(dataItem->valuestring), &sample_size);
    if (!sample) {
        cJSON_Delete(json);
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
        return;
    }

    pthread_mutex_lock(&api_mutex);
    g_req_music_token = tokenItem->valuestring;
    if (cJSON_IsString(storefrontItem)) {
        g_req_storefront_id = storefrontItem->valuestring;
    } else {
        g_req_storefront_id = NULL;
    }

    void **const kdContext = getKdContext(adamIdItem->valuestring, uriItem->valuestring);
    
    if (kdContext != NULL) {
        NfcRKVnxuKZy04KWbdFu71Ou(*kdContext, 5, sample, sample, sample_size);
    }

    g_req_music_token = NULL;
    g_req_storefront_id = NULL;
    pthread_mutex_unlock(&api_mutex);

    cJSON_Delete(json);

    if (kdContext != NULL) {
        size_t encoded_size = 0;
        char *encoded_sample = base64_encode(sample, sample_size, &encoded_size);
        
        cJSON *respJson = cJSON_CreateObject();
        cJSON_AddStringToObject(respJson, "data", encoded_sample);
        char *respStr = cJSON_PrintUnformatted(respJson);
        
        char header[512];
        snprintf(header, sizeof(header), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n", strlen(respStr));
        writefull(connfd, (void *)header, strlen(header));
        writefull(connfd, (void *)respStr, strlen(respStr));
        
        free(respStr);
        cJSON_Delete(respJson);
        free(encoded_sample);
    } else {
        const char *resp = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
    }
    free(sample);
}

extern uint8_t handle_cpp(int);

inline static int new_socket() {
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }
    const int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    static struct sockaddr_in serv_addr = {.sin_family = AF_INET};
    inet_pton(AF_INET, args_info.host_arg, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(args_info.decrypt_port_arg);
    if (bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("bind");
        return EXIT_FAILURE;
    }

    if (listen(fd, 5) == -1) {
        perror("listen");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[!] listening %s:%d\n", args_info.host_arg, args_info.decrypt_port_arg);
    // close(STDOUT_FILENO);

    static struct sockaddr_in peer_addr;
    static socklen_t peer_addr_size = sizeof(peer_addr);
    while (1) {
        const int connfd = accept4(fd, (struct sockaddr *)&peer_addr,
                                   &peer_addr_size, SOCK_CLOEXEC);
        if (connfd == -1) {
            if (errno == ENETDOWN || errno == EPROTO || errno == ENOPROTOOPT ||
                errno == EHOSTDOWN || errno == ENONET ||
                errno == EHOSTUNREACH || errno == EOPNOTSUPP ||
                errno == ENETUNREACH)
                continue;
            perror("accept4");
            return EXIT_FAILURE;
        }

        if (!handle_cpp(connfd)) {
            uint8_t autom = 1;
            _ZN22SVPlaybackLeaseManager12requestLeaseERKb(leaseMgr, &autom);
        }
        // if (sigsetjmp(catcher.env, 0) == 0) {
        //     catcher.do_jump = 1;
        //     handle(connfd);
        // }
        // catcher.do_jump = 0;

        if (close(connfd) == -1) {
            perror("close");
            return EXIT_FAILURE;
        }
    }
}


const char* get_m3u8_method_download(struct shared_ptr reqCtx, unsigned long adam) {
    void *purchase_request = malloc(1024);
    _ZN17storeservicescore15PurchaseRequestC2ERKNSt6__ndk110shared_ptrINS_14RequestContextEEE(purchase_request, &reqCtx);
    _ZN17storeservicescore15PurchaseRequest23setProcessDialogActionsEb(purchase_request, 1);
    union std_string urlBagKey = new_std_string("subDownload");
    _ZN17storeservicescore15PurchaseRequest12setURLBagKeyERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(purchase_request, &urlBagKey);
    char *buyParametersStr = malloc(128);
    sprintf(buyParametersStr, "salableAdamId=%lu&price=0&pricingParameters=SUBS&productType=S", adam);
    union std_string buyParameters = new_std_string(buyParametersStr);
    _ZN17storeservicescore15PurchaseRequest16setBuyParametersERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE(purchase_request, &buyParameters);
    _ZN17storeservicescore15PurchaseRequest3runEv(purchase_request);
    struct shared_ptr *response = _ZNK17storeservicescore15PurchaseRequest8responseEv(purchase_request);
    struct shared_ptr *error = _ZN17storeservicescore16PurchaseResponse5errorEv(response->obj);;
    if (error->obj == NULL) {
        struct std_vector items = _ZNK17storeservicescore16PurchaseResponse5itemsEv(response->obj);
        struct shared_ptr *firstItem = items.begin;
        struct std_vector assets = _ZNK17storeservicescore12PurchaseItem6assetsEv(firstItem->obj);
        struct shared_ptr *lastAsset = (struct shared_ptr *)assets.end - 1;
        union std_string *url_str = malloc(sizeof(union std_string));
        _ZNK17storeservicescore13PurchaseAsset3URLEv(url_str, lastAsset->obj);
        const char *url = std_string_data(url_str);
        if (url) {
            char *result = strdup(url);  // Make a copy
            free(url_str);
            return result;
        }
    } 
    return NULL;
}


const char* get_m3u8_method_play(uint8_t leaseMgr[16], unsigned long adam) {
    union std_string HLS = new_std_string_short_mode("HLS");
    struct std_vector HLSParam = new_std_vector(&HLS);
    static uint8_t z0 = 0;
    struct shared_ptr ptr_result;
    _ZN22SVPlaybackLeaseManager12requestAssetERKmRKNSt6__ndk16vectorINS2_12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEENS7_IS9_EEEERKb(
        &ptr_result, leaseMgr, &adam, &HLSParam, &z0
    );
    
    if (ptr_result.obj == NULL) {
        return NULL;
    }

    if (_ZNK23SVPlaybackAssetResponse13hasValidAssetEv(ptr_result.obj)) {
        struct shared_ptr *playbackAsset = _ZNK23SVPlaybackAssetResponse13playbackAssetEv(ptr_result.obj);
        if (playbackAsset == NULL || playbackAsset->obj == NULL) {
            return NULL;
        }

        union std_string *m3u8 = malloc(sizeof(union std_string));
        if (m3u8 == NULL) {
            return NULL;
        }

        void *playbackObj = playbackAsset->obj;
        _ZNK17storeservicescore13PlaybackAsset9URLStringEv(m3u8, playbackObj);

        if (m3u8 == NULL || std_string_data(m3u8) == NULL) {
            free(m3u8);
            return NULL;
        }
        
        const char *m3u8_str = std_string_data(m3u8);
        if (m3u8_str) {
            char *result = strdup(m3u8_str);  // Make a copy
            free(m3u8);
            return result;
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }
}

void handle_m3u8(const int connfd) {
    char buffer[4096];
    ssize_t n = read(connfd, buffer, sizeof(buffer) - 1);
    if (n <= 0) return;
    buffer[n] = '\0';

    // Check for POST
    if (strncmp(buffer, "POST", 4) != 0) {
        const char *resp = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
        return;
    }

    // Find body
    char *body = strstr(buffer, "\r\n\r\n");
    if (!body) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
        return;
    }
    body += 4;

    cJSON *json = cJSON_Parse(body);
    if (!json) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
        return;
    }

    cJSON *adamIdItem = cJSON_GetObjectItemCaseSensitive(json, "adamId");
    cJSON *tokenItem = cJSON_GetObjectItemCaseSensitive(json, "token");
    cJSON *storefrontItem = cJSON_GetObjectItemCaseSensitive(json, "storefront");
    cJSON *actionItem = cJSON_GetObjectItemCaseSensitive(json, "action"); // "play" or "download"

    if (!cJSON_IsString(adamIdItem) || !cJSON_IsString(tokenItem)) {
        cJSON_Delete(json);
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
        return;
    }

    unsigned long adamID = strtoul(adamIdItem->valuestring, NULL, 10);
    
    pthread_mutex_lock(&api_mutex);
    g_req_music_token = tokenItem->valuestring;
    if (cJSON_IsString(storefrontItem)) {
        g_req_storefront_id = storefrontItem->valuestring;
    } else {
        g_req_storefront_id = NULL;
    }

    const char *m3u8 = NULL;
    int is_download = (actionItem && cJSON_IsString(actionItem) && strcmp(actionItem->valuestring, "download") == 0);
    
    if (is_download) {
        m3u8 = get_m3u8_method_download(reqCtx, adamID);
    } else {
        m3u8 = get_m3u8_method_play(leaseMgr, adamID);
    }

    g_req_music_token = NULL;
    g_req_storefront_id = NULL;
    pthread_mutex_unlock(&api_mutex);

    cJSON_Delete(json);

    if (m3u8) {
        cJSON *respJson = cJSON_CreateObject();
        cJSON_AddStringToObject(respJson, "url", m3u8);
        char *respStr = cJSON_PrintUnformatted(respJson);
        
        char header[512];
        snprintf(header, sizeof(header), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n", strlen(respStr));
        writefull(connfd, (void *)header, strlen(header));
        writefull(connfd, (void *)respStr, strlen(respStr));
        
        free(respStr);
        cJSON_Delete(respJson);
        free((void *)m3u8);
    } else {
        const char *resp = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
        writefull(connfd, (void *)resp, strlen(resp));
    }
}

static inline void *new_socket_m3u8(void *args) {
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd == -1) {
        perror("socket");
    }
    const int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    static struct sockaddr_in serv_addr = {.sin_family = AF_INET};
    inet_pton(AF_INET, args_info.host_arg, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(args_info.m3u8_port_arg);
    if (bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("bind");
    }

    if (listen(fd, 5) == -1) {
        perror("listen");
    }

    fprintf(stderr, "[!] listening m3u8 request on %s:%d\n", args_info.host_arg, args_info.m3u8_port_arg);
    // close(STDOUT_FILENO);

    static struct sockaddr_in peer_addr;
    static socklen_t peer_addr_size = sizeof(peer_addr);
    while (1) {
        const int connfd = accept4(fd, (struct sockaddr *)&peer_addr,
                                   &peer_addr_size, SOCK_CLOEXEC);
        if (connfd == -1) {
            if (errno == ENETDOWN || errno == EPROTO || errno == ENOPROTOOPT ||
                errno == EHOSTDOWN || errno == ENONET ||
                errno == EHOSTUNREACH || errno == EOPNOTSUPP ||
                errno == ENETUNREACH)
                continue;
            perror("accept4");
            
        }

        handle_m3u8(connfd);

        if (close(connfd) == -1) {
            perror("close");
        }
    }
}

void handle_account(const int connfd)
{
    char buffer[4096];
    ssize_t n = read(connfd, buffer, sizeof(buffer) - 1);
    if (n <= 0) {
        return;
    }
    buffer[n] = '\0';

    // Parse HTTP request (simple check for GET)
    if (strncmp(buffer, "GET", 3) != 0 && strncmp(buffer, "POST", 4) != 0) {
        const char *error_response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n";
        writefull(connfd, (void *)error_response, strlen(error_response));
        return;
    }

    // Format JSON response body
    size_t json_size = 1024;
    char *json_body = (char *)malloc(json_size);
    if (json_body == NULL)
    {
        fprintf(stderr, "[.] failed to allocate memory for account response\n");
        const char *error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n";
        writefull(connfd, (void *)error_response, strlen(error_response));
        return;
    }

    snprintf(json_body, json_size, "{\"storefront_id\":\"%s\",\"dev_token\":\"%s\",\"music_token\":\"%s\"}",
             g_storefront_id, g_dev_token, g_music_token);

    int json_len = strlen(json_body);

    // Format HTTP response with headers
    size_t response_size = 512;
    char *http_response = (char *)malloc(response_size);
    if (http_response == NULL)
    {
        fprintf(stderr, "[.] failed to allocate memory for HTTP response\n");
        free(json_body);
        const char *error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n";
        writefull(connfd, (void *)error_response, strlen(error_response));
        return;
    }

    snprintf(http_response, response_size, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
             json_len);

    fprintf(stderr, "[.] returning account info, storefront: %s\n", g_storefront_id);
    writefull(connfd, http_response, strlen(http_response));
    writefull(connfd, json_body, json_len);

    free(http_response);
    free(json_body);
}

char* get_account_storefront_id(struct shared_ptr reqCtx) {
    union std_string *region = malloc(sizeof(union std_string));
    struct shared_ptr urlbag = {.obj = 0x0, .ctrl_blk = 0x0};
    _ZNK17storeservicescore14RequestContext20storeFrontIdentifierERKNSt6__ndk110shared_ptrINS_6URLBagEEE(region, reqCtx.obj, &urlbag);
    const char *region_str = std_string_data(region);
    if (region_str) {
        char *result = strdup(region_str); 
        free(region);
        return result;
    } 
    return NULL;
}

void write_storefront_id(void) {
    FILE *fp = fopen(strcat_b(args_info.base_dir_arg, "/STOREFRONT_ID"), "w");
    printf("[+] StoreFront ID: %s\n", g_storefront_id);
    fprintf(fp, "%s", g_storefront_id);
    fclose(fp);
}

char *get_guid() {
    char *ret[2];
    _ZN17storeservicescore10DeviceGUID4guidEv(ret, GUID.obj);
    char *guid = _ZNK13mediaplatform4Data5bytesEv(ret[0]);
    return guid;
}

long long getCurrentTimeMillis() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000LL + tv.tv_usec / 1000;
}


char *get_music_user_token(char *guid, char *authToken, struct shared_ptr reqCtx){
    uint8_t ptr[480];
    *(void **)(ptr) =
        &_ZTVNSt6__ndk120__shared_ptr_emplaceIN13mediaplatform11HTTPMessageENS_9allocatorIS2_EEEE +
        2;
    struct shared_ptr httpMessage = {.obj = ptr + 32, .ctrl_blk = ptr};
    union std_string url = new_std_string("https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/createMusicToken");
    union std_string method = new_std_string("POST");
    _ZN13mediaplatform11HTTPMessageC2ENSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES7_(httpMessage.obj, &url, &method);
    union std_string contentTypeHeader = new_std_string("Content-Type");
    union std_string contentTypeValue = new_std_string("application/json; charset=UTF-8");
    _ZN13mediaplatform11HTTPMessage9setHeaderERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(httpMessage.obj, &contentTypeHeader, &contentTypeValue);
    union std_string expectHeader = new_std_string("Expect");
    union std_string expectValue = new_std_string("");
    _ZN13mediaplatform11HTTPMessage9setHeaderERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(httpMessage.obj, &expectHeader, &expectValue);
    union std_string bundleIdHeader = new_std_string("X-Apple-Requesting-Bundle-Id");
    union std_string bundleIdValue = new_std_string("com.apple.android.music");
    _ZN13mediaplatform11HTTPMessage9setHeaderERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(httpMessage.obj, &bundleIdHeader, &bundleIdValue);
    union std_string bundleVersionHeader = new_std_string("X-Apple-Requesting-Bundle-Version");
    union std_string bundleVersionValue = new_std_string("Music/4.9 Android/10 model/Samsung S9 build/7663313 (dt:66)");
    _ZN13mediaplatform11HTTPMessage9setHeaderERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(httpMessage.obj, &bundleVersionHeader, &bundleVersionValue);
    size_t body_size = 512;
    char *body = (char *)malloc(body_size);
    if (body == NULL) {
        return "";
    }

    snprintf(body, body_size, "{\"guid\":\"%s\",\"assertion\":\"%s\",\"tcc-acceptance-date\":\"%lld\"}", guid, authToken, getCurrentTimeMillis());

    _ZN13mediaplatform11HTTPMessage11setBodyDataEPcm(httpMessage.obj, body, strlen(body));
    free(body);
    uint8_t urlRequest[512];
    _ZN17storeservicescore10URLRequestC2ERKNSt6__ndk110shared_ptrIN13mediaplatform11HTTPMessageEEERKNS2_INS_14RequestContextEEE(urlRequest, &httpMessage, &reqCtx);
    _ZN17storeservicescore10URLRequest3runEv(urlRequest);
    struct shared_ptr *err = _ZNK17storeservicescore10URLRequest5errorEv(urlRequest);
    if (err->obj != NULL) {
        return "";
    }
    struct shared_ptr *urlResp = _ZNK17storeservicescore10URLRequest8responseEv(urlRequest);
    struct shared_ptr *resp = _ZNK17storeservicescore11URLResponse18underlyingResponseEv(urlResp->obj);
    void *http_message_obj = resp->obj;
    void** data_ptr_location = (void**)((char*)http_message_obj + 48);
    void* data_ptr = *data_ptr_location;
    char *respBody = _ZNK13mediaplatform4Data5bytesEv(data_ptr);
    cJSON *json = cJSON_Parse(respBody);
    cJSON *token_obj = cJSON_GetObjectItemCaseSensitive(json, "music_token");
    char *token = cJSON_GetStringValue(token_obj);
    char *result = strdup(token);
    return result;
}


char* get_dev_token(struct shared_ptr reqCtx) {
    uint8_t ptr[480];
    *(void **)(ptr) =
        &_ZTVNSt6__ndk120__shared_ptr_emplaceIN13mediaplatform11HTTPMessageENS_9allocatorIS2_EEEE +
        2;
    struct shared_ptr httpMessage = {.obj = ptr + 32, .ctrl_blk = ptr};
    union std_string url = new_std_string("https://sf-api-token-service.itunes.apple.com/apiToken");
    union std_string method = new_std_string("GET");
    _ZN13mediaplatform11HTTPMessageC2ENSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES7_(httpMessage.obj, &url, &method);
    uint8_t urlRequest[512];
    _ZN17storeservicescore10URLRequestC2ERKNSt6__ndk110shared_ptrIN13mediaplatform11HTTPMessageEEERKNS2_INS_14RequestContextEEE(urlRequest, &httpMessage, &reqCtx);
    union std_string clientIdName = new_std_string("clientId");
    union std_string clientIdValue = new_std_string("musicAndroid");
    _ZN17storeservicescore10URLRequest19setRequestParameterERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(urlRequest, &clientIdName, &clientIdValue);
    union std_string versionName = new_std_string("version");
    union std_string versionValue = new_std_string("1");
    _ZN17storeservicescore10URLRequest19setRequestParameterERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_(urlRequest, &versionName, &versionValue);
    _ZN17storeservicescore10URLRequest3runEv(urlRequest);
    struct shared_ptr *err = _ZNK17storeservicescore10URLRequest5errorEv(urlRequest);
    if (err->obj != NULL) {
        return "";
    }
    struct shared_ptr *urlResp = _ZNK17storeservicescore10URLRequest8responseEv(urlRequest);
    struct shared_ptr *resp = _ZNK17storeservicescore11URLResponse18underlyingResponseEv(urlResp->obj);
    void *http_message_obj = resp->obj;
    void** data_ptr_location = (void**)((char*)http_message_obj + 48);
    void* data_ptr = *data_ptr_location;
    char *respBody = _ZNK13mediaplatform4Data5bytesEv(data_ptr);
    cJSON *json = cJSON_Parse(respBody);
    cJSON *token_obj = cJSON_GetObjectItemCaseSensitive(json, "token");
    char *token = cJSON_GetStringValue(token_obj);
    char *result = strdup(token);
    return result;
}

void write_music_token(void) {
    int token_file_available = 0;
    if (file_exists(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"))) {
        FILE *fp = fopen(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"), "r");
        if (NULL != fp) {
            fseek (fp, 0, SEEK_END);
            long size = ftell(fp);

            if (0 != size) {
                token_file_available = 1;
            }
        }
    }
    if (token_file_available) {
        char token[256];
        FILE *fp = fopen(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"), "r");
        fgets(token, sizeof(token), fp);
        printf("[+] Music-Token: %.14s...\n", token);
        return;
    }
    FILE *fp = fopen(strcat_b(args_info.base_dir_arg, "/MUSIC_TOKEN"), "w");
    printf("[+] Music-Token: %.14s...\n", g_music_token);
    fprintf(fp, "%s", g_music_token);
    fclose(fp);
}

int offline_available() {
    struct shared_ptr *fairplay = malloc(16);
    _ZN17storeservicescore14RequestContext8fairPlayEv(fairplay, reqCtx.obj);
    struct std_vector fairplay_status = _ZN17storeservicescore8FairPlay21getSubscriptionStatusEv(fairplay->obj);
    char *begin_ptr = (char*)fairplay_status.begin;
    char *second_item_ptr = begin_ptr + 16;
    int state = *(int*)((char*)second_item_ptr + 8);
    if (state == 2 || state == 3) { // kFPSubscriptionCanPlayContent, kFPSubscriptionCanStreamAndPlayContent
        return 1;
    } 
    return 0;
}

int main(int argc, char *argv[]) {
    cmdline_parser(argc, argv, &args_info);
    char *copy_that_needs_to_be_freed = NULL;
    split_string_safe(args_info.device_info_arg, "/", device_infos, 9, &copy_that_needs_to_be_freed);

    #ifndef MyRelease
    subhook_install(subhook_new(_ZN13mediaplatform26DebugLogEnabledForPriorityENS_11LogPriorityE, allDebug, SUBHOOK_64BIT_OFFSET));
    curl_hook = subhook_new(curl_easy_setopt, curl_easy_setopt_hook, SUBHOOK_64BIT_OFFSET);
    subhook_install(curl_hook);
    curl_perform_hook = subhook_new(curl_easy_perform, curl_easy_perform_hook, SUBHOOK_64BIT_OFFSET);
    subhook_install(curl_perform_hook);
    subhook_install(subhook_new(__android_log_print, android_log_print_hook, SUBHOOK_64BIT_OFFSET));
    subhook_install(subhook_new(__android_log_write, android_log_write_hook, SUBHOOK_64BIT_OFFSET));
    #endif

    init();
    reqCtx = init_ctx();
    
    _ZN22SVPlaybackLeaseManagerC2ERKNSt6__ndk18functionIFvRKiEEERKNS1_IFvRKNS0_10shared_ptrIN17storeservicescore19StoreErrorConditionEEEEEE(
        leaseMgr, &endLeaseCallback, &pbErrCallback);
    uint8_t autom = 1;
    _ZN22SVPlaybackLeaseManager25refreshLeaseAutomaticallyERKb(leaseMgr, &autom);
    _ZN22SVPlaybackLeaseManager12requestLeaseERKb(leaseMgr, &autom);
    FHinstance = _ZN21SVFootHillSessionCtrl8instanceEv();

    offlineFlag = offline_available();
    if (offlineFlag) {
        printf("[+] This account supports offline channel\n");
    }

    pthread_t m3u8_thread;
    pthread_create(&m3u8_thread, NULL, &new_socket_m3u8, NULL);
    pthread_detach(m3u8_thread);

    return new_socket();
}
