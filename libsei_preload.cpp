#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
constexpr uint32_t kCrcInit = 0xFFFFFFFFu;

const uint32_t kCrc32cTable[256] = {
    0x00000000u, 0xF26B8303u, 0xE13B70F7u, 0x1350F3F4u, 0xC79A971Fu,
    0x35F1141Cu, 0x26A1E7E8u, 0xD4CA64EBu, 0x8AD958CFu, 0x78B2DBCCu,
    0x6BE22838u, 0x9989AB3Bu, 0x4D43CFD0u, 0xBF284CD3u, 0xAC78BF27u,
    0x5E133C24u, 0x105EC76Fu, 0xE235446Cu, 0xF165B798u, 0x030E349Bu,
    0xD7C45070u, 0x25AFD373u, 0x36FF2087u, 0xC494A384u, 0x9A879FA0u,
    0x68EC1CA3u, 0x7BBCEF57u, 0x89D76C54u, 0x5D1D08BFu, 0xAF768BBCu,
    0xBC267848u, 0x4E4DFB4Bu, 0x20BD8EDEu, 0xD2D60DDDu, 0xC186FE29u,
    0x33ED7D2Au, 0xE72719C1u, 0x154C9AC2u, 0x061C6936u, 0xF477EA35u,
    0xAA64D611u, 0x580F5512u, 0x4B5FA6E6u, 0xB93425E5u, 0x6DFE410Eu,
    0x9F95C20Du, 0x8CC531F9u, 0x7EAEB2FAu, 0x30E349B1u, 0xC288CAB2u,
    0xD1D83946u, 0x23B3BA45u, 0xF779DEAEu, 0x05125DADu, 0x1642AE59u,
    0xE4292D5Au, 0xBA3A117Eu, 0x4851927Du, 0x5B016189u, 0xA96AE28Au,
    0x7DA08661u, 0x8FCB0562u, 0x9C9BF696u, 0x6EF07595u, 0x417B1DBCu,
    0xB3109EBFu, 0xA0406D4Bu, 0x522BEE48u, 0x86E18AA3u, 0x748A09A0u,
    0x67DAFA54u, 0x95B17957u, 0xCBA24573u, 0x39C9C670u, 0x2A993584u,
    0xD8F2B687u, 0x0C38D26Cu, 0xFE53516Fu, 0xED03A29Bu, 0x1F682198u,
    0x5125DAD3u, 0xA34E59D0u, 0xB01EAA24u, 0x42752927u, 0x96BF4DCCu,
    0x64D4CECFu, 0x77843D3Bu, 0x85EFBE38u, 0xDBFC821Cu, 0x2997011Fu,
    0x3AC7F2EBu, 0xC8AC71E8u, 0x1C661503u, 0xEE0D9600u, 0xFD5D65F4u,
    0x0F36E6F7u, 0x61C69362u, 0x93AD1061u, 0x80FDE395u, 0x72966096u,
    0xA65C047Du, 0x5437877Eu, 0x4767748Au, 0xB50CF789u, 0xEB1FCBADu,
    0x197448AEu, 0x0A24BB5Au, 0xF84F3859u, 0x2C855CB2u, 0xDEEEDFB1u,
    0xCDBE2C45u, 0x3FD5AF46u, 0x7198540Du, 0x83F3D70Eu, 0x90A324FAu,
    0x62C8A7F9u, 0xB602C312u, 0x44694011u, 0x5739B3E5u, 0xA55230E6u,
    0xFB410CC2u, 0x092A8FC1u, 0x1A7A7C35u, 0xE811FF36u, 0x3CDB9BDDu,
    0xCEB018DEu, 0xDDE0EB2Au, 0x2F8B6829u, 0x82F63B78u, 0x709DB87Bu,
    0x63CD4B8Fu, 0x91A6C88Cu, 0x456CAC67u, 0xB7072F64u, 0xA457DC90u,
    0x563C5F93u, 0x082F63B7u, 0xFA44E0B4u, 0xE9141340u, 0x1B7F9043u,
    0xCFB5F4A8u, 0x3DDE77ABu, 0x2E8E845Fu, 0xDCE5075Cu, 0x92A8FC17u,
    0x60C37F14u, 0x73938CE0u, 0x81F80FE3u, 0x55326B08u, 0xA759E80Bu,
    0xB4091BFFu, 0x466298FCu, 0x1871A4D8u, 0xEA1A27DBu, 0xF94AD42Fu,
    0x0B21572Cu, 0xDFEB33C7u, 0x2D80B0C4u, 0x3ED04330u, 0xCCBBC033u,
    0xA24BB5A6u, 0x502036A5u, 0x4370C551u, 0xB11B4652u, 0x65D122B9u,
    0x97BAA1BAu, 0x84EA524Eu, 0x7681D14Du, 0x2892ED69u, 0xDAF96E6Au,
    0xC9A99D9Eu, 0x3BC21E9Du, 0xEF087A76u, 0x1D63F975u, 0x0E330A81u,
    0xFC588982u, 0xB21572C9u, 0x407EF1CAu, 0x532E023Eu, 0xA145813Du,
    0x758FE5D6u, 0x87E466D5u, 0x94B49521u, 0x66DF1622u, 0x38CC2A06u,
    0xCAA7A905u, 0xD9F75AF1u, 0x2B9CD9F2u, 0xFF56BD19u, 0x0D3D3E1Au,
    0x1E6DCDEEu, 0xEC064EEDu, 0xC38D26C4u, 0x31E6A5C7u, 0x22B65633u,
    0xD0DDD530u, 0x0417B1DBu, 0xF67C32D8u, 0xE52CC12Cu, 0x1747422Fu,
    0x49547E0Bu, 0xBB3FFD08u, 0xA86F0EFCu, 0x5A048DFFu, 0x8ECEE914u,
    0x7CA56A17u, 0x6FF599E3u, 0x9D9E1AE0u, 0xD3D3E1ABu, 0x21B862A8u,
    0x32E8915Cu, 0xC083125Fu, 0x144976B4u, 0xE622F5B7u, 0xF5720643u,
    0x07198540u, 0x590AB964u, 0xAB613A67u, 0xB831C993u, 0x4A5A4A90u,
    0x9E902E7Bu, 0x6CFBAD78u, 0x7FAB5E8Cu, 0x8DC0DD8Fu, 0xE330A81Au,
    0x115B2B19u, 0x020BD8EDu, 0xF0605BEEu, 0x24AA3F05u, 0xD6C1BC06u,
    0xC5914FF2u, 0x37FACCF1u, 0x69E9F0D5u, 0x9B8273D6u, 0x88D28022u,
    0x7AB90321u, 0xAE7367CAu, 0x5C18E4C9u, 0x4F48173Du, 0xBD23943Eu,
    0xF36E6F75u, 0x0105EC76u, 0x12551F82u, 0xE03E9C81u, 0x34F4F86Au,
    0xC69F7B69u, 0xD5CF889Du, 0x27A40B9Eu, 0x79B737BAu, 0x8BDCB4B9u,
    0x988C474Du, 0x6AE7C44Eu, 0xBE2DA0A5u, 0x4C4623A6u, 0x5F16D052u,
    0xAD7D5351u
};

uint32_t crc32c_compute(const uint8_t *data, size_t len) {
    uint32_t crc = kCrcInit;
    for (size_t i = 0; i < len; ++i) {
        crc = kCrc32cTable[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return ~crc;
}

bool g_log_enabled = false;

void log_line(const std::string &msg) {
    if (!g_log_enabled) return;
    std::cerr << "[sei-preload] " << msg << "\n";
}

enum class Protocol {
    Unknown,
    Memcached,
    Http
};

enum class Mode {
    Auto,
    Memcached,
    Http
};

Mode g_mode = Mode::Auto;
std::atomic<bool> g_corrupt_once{false};

Protocol mode_to_proto(Mode mode) {
    if (mode == Mode::Memcached) return Protocol::Memcached;
    if (mode == Mode::Http) return Protocol::Http;
    return Protocol::Unknown;
}

Protocol port_to_proto(uint16_t port) {
    if (port == 11211) return Protocol::Memcached;
    if (port == 8080) return Protocol::Http;
    return Protocol::Unknown;
}

struct ConnState {
    Protocol proto = Protocol::Unknown;

    // memcached outgoing
    enum class ReqState { Line, Value } req_state = ReqState::Line;
    size_t expected_value = 0;
    std::vector<uint8_t> mc_out_buf;

    // memcached incoming
    enum class RespState { Line, Value, Trailer } resp_state = RespState::Line;
    size_t expected_resp_value = 0;
    bool resp_in_multiline = false;
    std::vector<uint8_t> mc_in_buf;
    std::vector<uint8_t> mc_resp_buf;

    // http outgoing
    std::vector<uint8_t> http_out_buf;

    // http incoming
    std::vector<uint8_t> http_in_buf;

    // data ready to deliver to app
    std::vector<uint8_t> ready_out;
    size_t ready_out_off = 0;
};

std::mutex g_state_mu;
std::unordered_map<int, ConnState> g_state;

ConnState &get_state(int fd) {
    std::lock_guard<std::mutex> lock(g_state_mu);
    return g_state[fd];
}

void erase_state(int fd) {
    std::lock_guard<std::mutex> lock(g_state_mu);
    g_state.erase(fd);
}

using connect_fn = int (*)(int, const struct sockaddr *, socklen_t);
using send_fn = ssize_t (*)(int, const void *, size_t, int);
using recv_fn = ssize_t (*)(int, void *, size_t, int);
using write_fn = ssize_t (*)(int, const void *, size_t);
using read_fn = ssize_t (*)(int, void *, size_t);
using writev_fn = ssize_t (*)(int, const struct iovec *, int);
using readv_fn = ssize_t (*)(int, const struct iovec *, int);
using sendmsg_fn = ssize_t (*)(int, const struct msghdr *, int);
using recvmsg_fn = ssize_t (*)(int, struct msghdr *, int);
using close_fn = int (*)(int);

connect_fn real_connect = nullptr;
send_fn real_send = nullptr;
recv_fn real_recv = nullptr;
write_fn real_write = nullptr;
read_fn real_read = nullptr;
writev_fn real_writev = nullptr;
readv_fn real_readv = nullptr;
sendmsg_fn real_sendmsg = nullptr;
recvmsg_fn real_recvmsg = nullptr;
close_fn real_close = nullptr;

void init_real_fns() {
    real_connect = reinterpret_cast<connect_fn>(dlsym(RTLD_NEXT, "connect"));
    real_send = reinterpret_cast<send_fn>(dlsym(RTLD_NEXT, "send"));
    real_recv = reinterpret_cast<recv_fn>(dlsym(RTLD_NEXT, "recv"));
    real_write = reinterpret_cast<write_fn>(dlsym(RTLD_NEXT, "write"));
    real_read = reinterpret_cast<read_fn>(dlsym(RTLD_NEXT, "read"));
    real_writev = reinterpret_cast<writev_fn>(dlsym(RTLD_NEXT, "writev"));
    real_readv = reinterpret_cast<readv_fn>(dlsym(RTLD_NEXT, "readv"));
    real_sendmsg = reinterpret_cast<sendmsg_fn>(dlsym(RTLD_NEXT, "sendmsg"));
    real_recvmsg = reinterpret_cast<recvmsg_fn>(dlsym(RTLD_NEXT, "recvmsg"));
    real_close = reinterpret_cast<close_fn>(dlsym(RTLD_NEXT, "close"));
}

std::vector<std::string> split_tokens(const std::string &line) {
    std::istringstream iss(line);
    std::vector<std::string> tokens;
    std::string tok;
    while (iss >> tok) {
        tokens.push_back(tok);
    }
    return tokens;
}

bool parse_value_bytes(const std::string &line, size_t *out_bytes) {
    auto tokens = split_tokens(line);
    if (tokens.size() < 4) {
        return false;
    }
    try {
        *out_bytes = static_cast<size_t>(std::stoul(tokens[3]));
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_request_bytes(const std::string &line, size_t *out_bytes) {
    auto tokens = split_tokens(line);
    if (tokens.size() < 5) {
        return false;
    }
    try {
        *out_bytes = static_cast<size_t>(std::stoul(tokens[4]));
        return true;
    } catch (...) {
        return false;
    }
}

bool is_value_command(const std::string &cmd) {
    return cmd == "set" || cmd == "add" || cmd == "replace" || cmd == "append" ||
           cmd == "prepend" || cmd == "cas";
}

bool send_all(int fd, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = real_send(fd, data + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool mc_process_outgoing(ConnState &st, int fd) {
    size_t pos = 0;
    while (pos < st.mc_out_buf.size()) {
        if (st.req_state == ConnState::ReqState::Line) {
            auto it = std::find(st.mc_out_buf.begin() + static_cast<long>(pos), st.mc_out_buf.end(), '\n');
            if (it == st.mc_out_buf.end()) break;
            size_t newline_idx = static_cast<size_t>(it - st.mc_out_buf.begin());
            size_t line_end = newline_idx;
            if (line_end > pos && st.mc_out_buf[line_end - 1] == '\r') {
                line_end--;
            }
            size_t line_len = line_end - pos;
            uint32_t crc = crc32c_compute(st.mc_out_buf.data() + pos, line_len);
            if (!send_all(fd, reinterpret_cast<uint8_t *>(&crc), sizeof(crc))) return false;
            if (!send_all(fd, st.mc_out_buf.data() + pos, newline_idx - pos + 1)) return false;

            std::string line(reinterpret_cast<const char *>(st.mc_out_buf.data() + pos), line_len);
            auto tokens = split_tokens(line);
            if (!tokens.empty() && is_value_command(tokens[0])) {
                size_t bytes = 0;
                if (!parse_request_bytes(line, &bytes)) return false;
                st.expected_value = bytes + 2;
                st.req_state = ConnState::ReqState::Value;
            }
            pos = newline_idx + 1;
        } else {
            if (st.mc_out_buf.size() - pos < st.expected_value) break;
            uint32_t crc = crc32c_compute(st.mc_out_buf.data() + pos, st.expected_value);
            if (!send_all(fd, reinterpret_cast<uint8_t *>(&crc), sizeof(crc))) return false;
            if (!send_all(fd, st.mc_out_buf.data() + pos, st.expected_value)) return false;
            pos += st.expected_value;
            st.req_state = ConnState::ReqState::Line;
        }
    }
    if (pos > 0) {
        st.mc_out_buf.erase(st.mc_out_buf.begin(), st.mc_out_buf.begin() + static_cast<long>(pos));
    }
    return true;
}

bool mc_process_incoming(ConnState &st, int fd) {
    (void)fd;
    size_t pos = 0;
    while (pos < st.mc_in_buf.size()) {
        if (st.resp_state == ConnState::RespState::Line) {
            auto it = std::find(st.mc_in_buf.begin() + static_cast<long>(pos), st.mc_in_buf.end(), '\n');
            if (it == st.mc_in_buf.end()) break;
            size_t newline_idx = static_cast<size_t>(it - st.mc_in_buf.begin());
            size_t line_end = newline_idx;
            if (line_end > pos && st.mc_in_buf[line_end - 1] == '\r') line_end--;
            size_t line_len = line_end - pos;
            st.mc_resp_buf.insert(st.mc_resp_buf.end(),
                                  st.mc_in_buf.begin() + static_cast<long>(pos),
                                  st.mc_in_buf.begin() + static_cast<long>(newline_idx + 1));

            std::string line(reinterpret_cast<const char *>(st.mc_in_buf.data() + pos), line_len);
            if (line == "END") {
                st.resp_state = ConnState::RespState::Trailer;
                st.resp_in_multiline = false;
            } else if (line.rfind("VALUE ", 0) == 0) {
                size_t bytes = 0;
                if (!parse_value_bytes(line, &bytes)) return false;
                st.expected_resp_value = bytes + 2;
                st.resp_in_multiline = true;
                st.resp_state = ConnState::RespState::Value;
            } else if (line.rfind("STAT ", 0) == 0 || line.rfind("ITEM ", 0) == 0) {
                st.resp_in_multiline = true;
            } else if (!st.resp_in_multiline) {
                st.resp_state = ConnState::RespState::Trailer;
            }
            pos = newline_idx + 1;
        } else if (st.resp_state == ConnState::RespState::Value) {
            if (st.mc_in_buf.size() - pos < st.expected_resp_value) break;
            st.mc_resp_buf.insert(st.mc_resp_buf.end(),
                                  st.mc_in_buf.begin() + static_cast<long>(pos),
                                  st.mc_in_buf.begin() + static_cast<long>(pos + st.expected_resp_value));
            pos += st.expected_resp_value;
            st.resp_state = ConnState::RespState::Line;
        } else {
            if (st.mc_in_buf.size() - pos < sizeof(uint32_t)) break;
            uint32_t wire_crc = 0;
            std::memcpy(&wire_crc, st.mc_in_buf.data() + pos, sizeof(uint32_t));
            if (g_corrupt_once.exchange(false)) {
                wire_crc ^= 0x1u;
            }
            uint32_t calc_crc = crc32c_compute(st.mc_resp_buf.data(), st.mc_resp_buf.size());
            if (wire_crc != calc_crc) {
                errno = EIO;
                return false;
            }
            st.ready_out = std::move(st.mc_resp_buf);
            st.ready_out_off = 0;
            st.mc_resp_buf.clear();
            st.resp_state = ConnState::RespState::Line;
            st.resp_in_multiline = false;
            pos += sizeof(uint32_t);
            break;
        }
    }
    if (pos > 0) {
        st.mc_in_buf.erase(st.mc_in_buf.begin(), st.mc_in_buf.begin() + static_cast<long>(pos));
    }
    return true;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string trim(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) start++;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return s.substr(start, end - start);
}

bool find_header_end(const std::vector<uint8_t> &buf, size_t *pos) {
    if (buf.size() < 4) return false;
    for (size_t i = 0; i + 3 < buf.size(); ++i) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            *pos = i;
            return true;
        }
    }
    return false;
}

struct Header {
    std::string name;
    std::string value;
    std::string name_lower;
};

struct HttpRequest {
    std::string method;
    std::string target;
    std::string version;
    std::vector<Header> headers;
    std::vector<uint8_t> body;
};

struct HttpResponse {
    std::string status_line;
    std::vector<Header> headers;
    std::vector<uint8_t> body;
    std::string crc_header;
    bool chunked = false;
};

bool parse_request_from_buffer(std::vector<uint8_t> &buf, HttpRequest &req) {
    size_t header_end = 0;
    if (!find_header_end(buf, &header_end)) return false;

    std::string header_block(reinterpret_cast<const char *>(buf.data()), header_end + 2);
    std::istringstream iss(header_block);
    std::string line;

    if (!std::getline(iss, line)) return false;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::istringstream start(line);
    if (!(start >> req.method >> req.target >> req.version)) return false;

    req.headers.clear();
    size_t content_length = 0;
    bool has_content_length = false;
    while (std::getline(iss, line)) {
        if (line == "\r" || line.empty()) break;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        Header h;
        h.name = line.substr(0, colon);
        h.value = trim(line.substr(colon + 1));
        h.name_lower = to_lower(h.name);
        if (h.name_lower == "content-length") {
            try {
                content_length = static_cast<size_t>(std::stoul(h.value));
                has_content_length = true;
            } catch (...) {
                return false;
            }
        }
        req.headers.push_back(std::move(h));
    }

    size_t body_start = header_end + 4;
    size_t needed = has_content_length ? content_length : 0;
    if (buf.size() < body_start + needed) return false;

    req.body.assign(buf.begin() + static_cast<long>(body_start),
                    buf.begin() + static_cast<long>(body_start + needed));
    buf.erase(buf.begin(), buf.begin() + static_cast<long>(body_start + needed));
    return true;
}

bool parse_response_from_buffer(std::vector<uint8_t> &buf, HttpResponse &resp, std::vector<uint8_t> &raw) {
    size_t header_end = 0;
    if (!find_header_end(buf, &header_end)) return false;

    std::string header_block(reinterpret_cast<const char *>(buf.data()), header_end + 2);
    std::istringstream iss(header_block);
    std::string line;

    if (!std::getline(iss, resp.status_line)) return false;
    if (!resp.status_line.empty() && resp.status_line.back() == '\r') resp.status_line.pop_back();

    resp.headers.clear();
    resp.crc_header.clear();
    resp.chunked = false;
    size_t content_length = 0;
    bool has_content_length = false;

    while (std::getline(iss, line)) {
        if (line == "\r" || line.empty()) break;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        Header h;
        h.name = line.substr(0, colon);
        h.value = trim(line.substr(colon + 1));
        h.name_lower = to_lower(h.name);
        if (h.name_lower == "content-length") {
            try {
                content_length = static_cast<size_t>(std::stoul(h.value));
                has_content_length = true;
            } catch (...) {
                return false;
            }
        } else if (h.name_lower == "transfer-encoding") {
            if (to_lower(h.value).find("chunked") != std::string::npos) {
                resp.chunked = true;
            }
        } else if (h.name_lower == "x-sei-crc") {
            resp.crc_header = h.value;
        }
        resp.headers.push_back(std::move(h));
    }

    size_t body_start = header_end + 4;
    if (resp.chunked) {
        size_t pos = body_start;
        std::vector<uint8_t> decoded;
        while (true) {
            size_t line_end = std::string::npos;
            for (size_t i = pos; i + 1 < buf.size(); ++i) {
                if (buf[i] == '\r' && buf[i + 1] == '\n') {
                    line_end = i;
                    break;
                }
            }
            if (line_end == std::string::npos) return false;
            std::string size_line(reinterpret_cast<const char *>(buf.data() + pos), line_end - pos);
            auto semicolon = size_line.find(';');
            if (semicolon != std::string::npos) size_line = size_line.substr(0, semicolon);
            size_t chunk_size = 0;
            try {
                chunk_size = static_cast<size_t>(std::stoul(size_line, nullptr, 16));
            } catch (...) {
                return false;
            }
            pos = line_end + 2;
            if (chunk_size == 0) {
                while (true) {
                    size_t trailer_end = std::string::npos;
                    for (size_t i = pos; i + 1 < buf.size(); ++i) {
                        if (buf[i] == '\r' && buf[i + 1] == '\n') {
                            trailer_end = i;
                            break;
                        }
                    }
                    if (trailer_end == std::string::npos) return false;
                    pos = trailer_end + 2;
                    if (trailer_end == pos - 2) break;
                }
                resp.body = std::move(decoded);
                raw.assign(buf.begin(), buf.begin() + static_cast<long>(pos));
                buf.erase(buf.begin(), buf.begin() + static_cast<long>(pos));
                return true;
            }
            if (buf.size() < pos + chunk_size + 2) return false;
            decoded.insert(decoded.end(), buf.begin() + static_cast<long>(pos),
                           buf.begin() + static_cast<long>(pos + chunk_size));
            pos += chunk_size;
            if (buf[pos] != '\r' || buf[pos + 1] != '\n') return false;
            pos += 2;
        }
    } else {
        if (!has_content_length) return false;
        size_t needed = content_length;
        if (buf.size() < body_start + needed) return false;
        resp.body.assign(buf.begin() + static_cast<long>(body_start),
                         buf.begin() + static_cast<long>(body_start + needed));
        raw.assign(buf.begin(), buf.begin() + static_cast<long>(body_start + needed));
        buf.erase(buf.begin(), buf.begin() + static_cast<long>(body_start + needed));
        return true;
    }
}

std::string format_crc_hex(uint32_t crc) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%08x", crc);
    return std::string(buf);
}

uint32_t parse_crc_hex(const std::string &s, bool *ok) {
    char *end = nullptr;
    unsigned long val = std::strtoul(s.c_str(), &end, 16);
    if (end == s.c_str() || *end != '\0') {
        *ok = false;
        return 0;
    }
    *ok = true;
    return static_cast<uint32_t>(val);
}

std::string build_request_bytes(const HttpRequest &req, const std::string &crc_hex) {
    std::ostringstream oss;
    oss << req.method << ' ' << req.target << ' ' << req.version << "\r\n";
    for (const auto &h : req.headers) {
        if (h.name_lower == "x-sei-crc") continue;
        oss << h.name << ": " << h.value << "\r\n";
    }
    oss << "X-SEI-CRC: " << crc_hex << "\r\n";
    oss << "\r\n";
    std::string head = oss.str();
    std::string out = head;
    out.append(reinterpret_cast<const char *>(req.body.data()), req.body.size());
    return out;
}

Protocol detect_protocol(int fd, const struct sockaddr *addr, socklen_t len) {
    (void)fd;
    if (g_mode != Mode::Auto) return mode_to_proto(g_mode);
    if (!addr) return Protocol::Unknown;
    uint16_t port = 0;
    if (addr->sa_family == AF_INET && len >= sizeof(sockaddr_in)) {
        const sockaddr_in *in = reinterpret_cast<const sockaddr_in *>(addr);
        port = ntohs(in->sin_port);
    } else if (addr->sa_family == AF_INET6 && len >= sizeof(sockaddr_in6)) {
        const sockaddr_in6 *in6 = reinterpret_cast<const sockaddr_in6 *>(addr);
        port = ntohs(in6->sin6_port);
    }
    return port_to_proto(port);
}

Protocol detect_protocol_peer(int fd) {
    if (g_mode != Mode::Auto) return mode_to_proto(g_mode);
    sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getpeername(fd, reinterpret_cast<sockaddr *>(&addr), &len) != 0) return Protocol::Unknown;
    return detect_protocol(fd, reinterpret_cast<sockaddr *>(&addr), len);
}

ssize_t handle_send(int fd, const void *buf, size_t len, int flags) {
    (void)flags;
    ConnState &st = get_state(fd);
    if (st.proto == Protocol::Unknown) {
        st.proto = detect_protocol_peer(fd);
    }
    if (st.proto == Protocol::Unknown) {
        return real_send(fd, buf, len, flags);
    }

    const uint8_t *data = reinterpret_cast<const uint8_t *>(buf);
    if (st.proto == Protocol::Memcached) {
        st.mc_out_buf.insert(st.mc_out_buf.end(), data, data + len);
        if (!mc_process_outgoing(st, fd)) return -1;
        return static_cast<ssize_t>(len);
    }

    if (st.proto == Protocol::Http) {
        st.http_out_buf.insert(st.http_out_buf.end(), data, data + len);
        HttpRequest req;
        while (parse_request_from_buffer(st.http_out_buf, req)) {
            std::string method_for_crc = req.method;
            if (method_for_crc == "HEAD") method_for_crc = "GET";
            std::string target = req.target;
            auto frag = target.find('#');
            if (frag != std::string::npos) target = target.substr(0, frag);
            std::string crc_input = method_for_crc + " " + target;
            uint32_t crc = crc32c_compute(reinterpret_cast<const uint8_t *>(crc_input.data()), crc_input.size());
            std::string crc_hex = format_crc_hex(crc);
            std::string out_req = build_request_bytes(req, crc_hex);
            if (!send_all(fd, reinterpret_cast<const uint8_t *>(out_req.data()), out_req.size())) return -1;
        }
        return static_cast<ssize_t>(len);
    }

    return real_send(fd, buf, len, flags);
}

ssize_t handle_recv(int fd, void *buf, size_t len, int flags) {
    (void)flags;
    ConnState &st = get_state(fd);
    if (st.proto == Protocol::Unknown) {
        st.proto = detect_protocol_peer(fd);
    }
    if (st.proto == Protocol::Unknown) {
        return real_recv(fd, buf, len, flags);
    }

    if (!st.ready_out.empty()) {
        size_t avail = st.ready_out.size() - st.ready_out_off;
        size_t take = std::min(avail, len);
        std::memcpy(buf, st.ready_out.data() + st.ready_out_off, take);
        st.ready_out_off += take;
        if (st.ready_out_off == st.ready_out.size()) {
            st.ready_out.clear();
            st.ready_out_off = 0;
        }
        return static_cast<ssize_t>(take);
    }

    uint8_t tmp[4096];
    if (st.proto == Protocol::Memcached) {
        while (true) {
            ssize_t n = real_recv(fd, tmp, sizeof(tmp), 0);
            if (n <= 0) return n;
            st.mc_in_buf.insert(st.mc_in_buf.end(), tmp, tmp + n);
            if (!mc_process_incoming(st, fd)) return -1;
            if (!st.ready_out.empty()) {
                return handle_recv(fd, buf, len, flags);
            }
        }
    }

    if (st.proto == Protocol::Http) {
        while (true) {
            ssize_t n = real_recv(fd, tmp, sizeof(tmp), 0);
            if (n <= 0) return n;
            st.http_in_buf.insert(st.http_in_buf.end(), tmp, tmp + n);
            HttpResponse resp;
            std::vector<uint8_t> raw;
            if (parse_response_from_buffer(st.http_in_buf, resp, raw)) {
                bool ok = false;
                uint32_t expected_crc = parse_crc_hex(resp.crc_header, &ok);
                if (!ok) {
                    errno = EIO;
                    return -1;
                }
                if (g_corrupt_once.exchange(false)) expected_crc ^= 0x1u;
                uint32_t calc_crc = crc32c_compute(resp.body.data(), resp.body.size());
                if (expected_crc != calc_crc) {
                    errno = EIO;
                    return -1;
                }
                st.ready_out = std::move(raw);
                st.ready_out_off = 0;
                return handle_recv(fd, buf, len, flags);
            }
        }
    }

    return real_recv(fd, buf, len, flags);
}

}  // namespace

__attribute__((constructor)) void sei_preload_init() {
    init_real_fns();
    if (const char *env = std::getenv("SEI_PRELOAD_MODE")) {
        std::string mode = env;
        if (mode == "memcached") g_mode = Mode::Memcached;
        else if (mode == "http") g_mode = Mode::Http;
        else g_mode = Mode::Auto;
    }
    if (const char *env = std::getenv("SEI_PRELOAD_LOG")) {
        if (env[0] == '1') g_log_enabled = true;
    }
    if (const char *env = std::getenv("SEI_PRELOAD_CORRUPT")) {
        if (env[0] == '1') g_corrupt_once.store(true);
    }
    log_line("initialized");
}

extern "C" int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (!real_connect) init_real_fns();
    int rc = real_connect(fd, addr, len);
    if (rc == 0) {
        ConnState &st = get_state(fd);
        st.proto = detect_protocol(fd, addr, len);
    }
    return rc;
}

extern "C" ssize_t send(int fd, const void *buf, size_t len, int flags) {
    if (!real_send) init_real_fns();
    return handle_send(fd, buf, len, flags);
}

extern "C" ssize_t recv(int fd, void *buf, size_t len, int flags) {
    if (!real_recv) init_real_fns();
    return handle_recv(fd, buf, len, flags);
}

extern "C" ssize_t write(int fd, const void *buf, size_t count) {
    if (!real_write) init_real_fns();
    return handle_send(fd, buf, count, 0);
}

extern "C" ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) init_real_fns();
    return handle_recv(fd, buf, count, 0);
}

extern "C" ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    if (!real_writev) init_real_fns();
    std::vector<uint8_t> flat;
    size_t total = 0;
    for (int i = 0; i < iovcnt; ++i) total += iov[i].iov_len;
    flat.reserve(total);
    for (int i = 0; i < iovcnt; ++i) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(iov[i].iov_base);
        flat.insert(flat.end(), p, p + iov[i].iov_len);
    }
    ssize_t rc = handle_send(fd, flat.data(), flat.size(), 0);
    if (rc < 0) return rc;
    return static_cast<ssize_t>(total);
}

extern "C" ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    if (!real_readv) init_real_fns();
    size_t total = 0;
    for (int i = 0; i < iovcnt; ++i) total += iov[i].iov_len;
    std::vector<uint8_t> flat(total);
    ssize_t rc = handle_recv(fd, flat.data(), flat.size(), 0);
    if (rc <= 0) return rc;
    size_t copied = 0;
    for (int i = 0; i < iovcnt && copied < static_cast<size_t>(rc); ++i) {
        size_t take = std::min(static_cast<size_t>(rc) - copied, iov[i].iov_len);
        std::memcpy(iov[i].iov_base, flat.data() + copied, take);
        copied += take;
    }
    return rc;
}

extern "C" ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (!real_sendmsg) init_real_fns();
    if (!msg) return real_sendmsg(fd, msg, flags);
    std::vector<uint8_t> flat;
    size_t total = 0;
    for (size_t i = 0; i < msg->msg_iovlen; ++i) {
        total += msg->msg_iov[i].iov_len;
    }
    flat.reserve(total);
    for (size_t i = 0; i < msg->msg_iovlen; ++i) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(msg->msg_iov[i].iov_base);
        flat.insert(flat.end(), p, p + msg->msg_iov[i].iov_len);
    }
    return handle_send(fd, flat.data(), flat.size(), flags);
}

extern "C" ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    if (!real_recvmsg) init_real_fns();
    if (!msg) return real_recvmsg(fd, msg, flags);
    size_t total = 0;
    for (size_t i = 0; i < msg->msg_iovlen; ++i) {
        total += msg->msg_iov[i].iov_len;
    }
    std::vector<uint8_t> flat(total);
    ssize_t rc = handle_recv(fd, flat.data(), flat.size(), flags);
    if (rc <= 0) return rc;
    size_t copied = 0;
    for (size_t i = 0; i < msg->msg_iovlen && copied < static_cast<size_t>(rc); ++i) {
        size_t take = std::min(static_cast<size_t>(rc) - copied, msg->msg_iov[i].iov_len);
        std::memcpy(msg->msg_iov[i].iov_base, flat.data() + copied, take);
        copied += take;
    }
    return rc;
}

extern "C" int close(int fd) {
    if (!real_close) init_real_fns();
    erase_state(fd);
    return real_close(fd);
}
