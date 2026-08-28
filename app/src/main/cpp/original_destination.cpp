#include <jni.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

namespace {

jbyteArray encode(JNIEnv* env, int family, uint16_t network_port, const void* address, size_t size) {
    const jsize output_size = static_cast<jsize>(3 + size);
    auto* output = env->NewByteArray(output_size);
    if (output == nullptr) return nullptr;
    jbyte bytes[19]{};
    bytes[0] = static_cast<jbyte>(family == AF_INET ? 4 : 6);
    const uint16_t port = ntohs(network_port);
    bytes[1] = static_cast<jbyte>((port >> 8) & 0xff);
    bytes[2] = static_cast<jbyte>(port & 0xff);
    std::memcpy(bytes + 3, address, size);
    env->SetByteArrayRegion(output, 0, output_size, bytes);
    return output;
}

}  // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_org_xiyu_githubdirect_root_OriginalDestination_nativeLookup(
        JNIEnv* env, jobject /* thiz */, jint fd) {
    sockaddr_in original4{};
    socklen_t length4 = sizeof(original4);
    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &original4, &length4) == 0
            && original4.sin_family == AF_INET) {
        return encode(env, AF_INET, original4.sin_port, &original4.sin_addr, sizeof(original4.sin_addr));
    }

    sockaddr_in6 original6{};
    socklen_t length6 = sizeof(original6);
    if (getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &original6, &length6) == 0
            && original6.sin6_family == AF_INET6) {
        return encode(env, AF_INET6, original6.sin6_port, &original6.sin6_addr, sizeof(original6.sin6_addr));
    }
    return nullptr;
}
