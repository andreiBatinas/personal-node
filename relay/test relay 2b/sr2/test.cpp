#include "socks5.hpp"
///////////
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/make_shared.hpp>
#include <iostream>

namespace ba   = boost::asio;
namespace http = boost::beast::http;
namespace ssl  = boost::asio::ssl;
using namespace std::chrono_literals;
using ba::ip::tcp;

static constexpr auto connection_timeout = 1s;

int main()
{
    auto ios = boost::make_shared<ba::io_context>();

    auto ssl_ctx =
        boost::make_shared<ssl::context>(ssl::context_base::method::sslv23);
    ssl_ctx->set_verify_mode(ssl::verify_peer);
    //ssl_ctx->add_certificate_authority(ba::buffer(certs.data(), certs.size()));
    ssl_ctx->set_default_verify_paths(); // FOR DEMO

    auto ssl_socket =
        boost::make_shared<ssl::stream<tcp::socket>>(*ios, *ssl_ctx);

    auto& socket = ssl_socket->next_layer();

    tcp::resolver::query target("193.29.58.141", "443"); // 19002 ?

 #if 1
    std::future<void> conn_result = socks5::async_proxy_connect(
        socket, target, tcp::endpoint{{}, /*1080*/19002}, ba::use_future);

    std::thread th([ios] { ios->run(); });

    if (conn_result.wait_for(connection_timeout) ==
            std::future_status::timeout) {
        socket.cancel();
        // no need to throw, `conn_result.get()` will give operation_aborted
    }

    conn_result.get(); // may throw error
#else // synchronously as well:
    socks5::proxy_connect(socket, target, tcp::endpoint{{}, 1080});
#endif

    socket.set_option(tcp::no_delay(true));

    ssl_socket->handshake(ssl::stream_base::handshake_type::client);

    {
        http::request<http::empty_body> req(http::verb::get, "/", 11);
        req.set(http::field::host, "193.29.58.141");
        req.prepare_payload();

        http::write(*ssl_socket, req);
    }
    {
        http::response<http::string_body> res;
        boost::beast::flat_buffer buf;
        http::read(*ssl_socket, buf, res);

        std::cout << res;
    }

    th.join();
}
