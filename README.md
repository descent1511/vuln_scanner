
# Security Scanner Black-Box for Cloud

## 1. Giới thiệu
- **Mô tả tổng quan:** Cloud cung cấp dịch vụ public IP cho nhiều khách hàng. Đề tài này tập trung vào phát triển giải pháp bảo mật dạng black-box để đánh giá các lỗ hổng tiềm ẩn trên các asset của Cloud hoặc khách hàng có IP cấu hình được, và cảnh báo qua Telegram để xử lý kịp thời.
- **Mục tiêu:** Đánh giá và cảnh báo các lỗ hổng bảo mật thông qua public IP bằng cách thực hiện các quét bảo mật tự động.
  
## 2. Kiến trúc hệ thống
- **Các thành phần chính:**
  - **Scanner:** Quét các IP công khai của khách hàng và Cloud để tìm các lỗ hổng.
  - **Crawlers:** Tự động thu thập thông tin từ Web, Telegram group, và các nguồn threat intelligence khác.
  - **Cảnh báo:** Gửi thông báo qua Telegram khi phát hiện lỗ hổng.
  - **Backend:** Quản lý các tác vụ quét và thông tin thu thập từ các nguồn, cập nhật cơ sở dữ liệu và gửi cảnh báo.

- **Sơ đồ kiến trúc hệ thống:** 
<div style="text-align: center;">
    <img src="./images/VDT_P2_Architec.drawio-5.png" style="" alt="Architecture"/>
</div>

## 3. Kỹ năng và công nghệ
- **Ngôn ngữ lập trình:** Python, Django
- **Framework & công cụ:** 
  - **Django:** Dùng để xây dựng backend, quản lý cơ sở dữ liệu, và triển khai API xử lý các tác vụ quét bảo mật, cũng như tích hợp các công cụ liên quan.
  - **SpiderFoot:** Tự động thu thập thông tin từ các trang web, nhóm Telegram và các nguồn threat intelligence khác để đánh giá và phát hiện các mối đe dọa tiềm ẩn.
  - **OpenVAS:** Công cụ quét bảo mật mạnh mẽ, được dùng để kiểm tra các dịch vụ trên public IP và phát hiện lỗ hổng bảo mật của  Cloud và khách hàng.
  - **Telegram Bot:** Được tích hợp để gửi thông báo cảnh báo tức thời khi phát hiện các lỗ hổng hoặc mối đe dọa, giúp quản trị viên kịp thời phản hồi và xử lý.
  - **Celery:** Dùng để quản lý và chạy các tác vụ bất đồng bộ như lên lịch quét bảo mật và thu thập dữ liệu threat intelligence.
  - **Cơ sở dữ liệu (PostgreSQL):** Lưu trữ các kết quả quét, thông tin lỗ hổng, và lịch sử cảnh báo.


## 4. Phân tích bài toán
- **Mục tiêu bảo mật:** Tìm và đánh giá các lỗ hổng bảo mật có thể khai thác được từ bên ngoài trên các dịch vụ public.
- **Công cụ hỗ trợ:** Sử dụng các công cụ threat intelligence, OpenVAS và spiderfoot để thu thập và đánh giá thông tin bảo mật.

## 5. Quy trình làm việc
- **Bước 1: Cấu hình dải IP quét:** Quản trị viên có thể cấu hình dải IP cần quét cho hệ thống.
- **Bước 2: Thực hiện quét:** Hệ thống tiến hành quét các IP để thu thập thông tin và đánh giá bảo mật.
- **Bước 3: Thu thập thông tin threat intelligence:** Các crawler sẽ thu thập dữ liệu từ nhiều nguồn để đánh giá các mối đe dọa.
- **Bước 4: Cảnh báo qua Telegram:** Khi phát hiện lỗ hổng hoặc mối đe dọa, hệ thống sẽ tự động gửi cảnh báo tới quản trị viên qua Telegram.

## 6. Cài đặt và triển khai
- **Yêu cầu hệ thống:**
  - Python 3.x
  - Django
  - OpenVAS
  - Spiderfoot
  - Celery
  - PostgreSQL hoặc MySQL (cơ sở dữ liệu)
- **Hướng dẫn cài đặt:** Các bước chi tiết để cài đặt các thành phần trên.


## 7. Kết luận
- **Tầm quan trọng của hệ thống:** Hệ thống giúp Cloud và khách hàng bảo vệ các tài sản công khai của họ bằng cách phát hiện và xử lý kịp thời các lỗ hổng bảo mật.
- **Hướng phát triển tương lai:** Cải thiện các thuật toán phát hiện lỗ hổng và mở rộng khả năng quét.

## 8. Tài liệu tham khảo
- **OpenVAS documentation:** [link]
- **Telegram Bot API:** [link]
- **Threat Intelligence sources:** Các nguồn được sử dụng trong việc thu thập thông tin.
