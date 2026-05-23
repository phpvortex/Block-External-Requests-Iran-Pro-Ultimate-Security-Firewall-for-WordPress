<?php
/**
 * Plugin Name: Block External Requests - ایران پرو Ultimate
 * Plugin URI: https://ascript.ir
 * Description: فایروال امنیتی حرفه‌ای وردپرس جهت کنترل، مانیتورینگ و مسدودسازی درخواست‌های خارجی. دارای سیستم مدیریت دامنه‌های مجاز، لیست سیاه، لاگ امنیتی، جلوگیری از نشت اطلاعات و افزایش امنیت API.
 * Version: 9.0.0
 * Author: محمدامین کوهی
 * Author URI: https://ascript.ir
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Tested up to: 6.9
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: iranpro-firewall
 * Domain Path: /languages
 * Network: true
 */

if (!defined('ABSPATH')) {
    exit;
}

class Block_External_Requests_Iran_Pro {

    /**
     * option
     */
    private $option_name = 'ber_iran_settings';

    /**
     * logs
     */
    private $log_option = 'ber_iran_logs';

    /**
     * hosts
     */
    private $allowed_hosts = [];

    private $blocked_keywords = [];

    /**
     * تنظیمات پیشفرض
     */
    private $default_settings = [

        'enable_blocking'     => true,
        'reduce_timeout'      => true,
        'disable_emojis'      => true,
        'disable_gravatar'    => true,
        'disable_oembed'      => true,
        'clean_output'        => true,
        'enable_logging'      => true,

        /**
         * whitelist
         */
        'allowed_hosts' => "google.com
www.google.com
search.google.com
googleapis.com
fonts.googleapis.com
fonts.gstatic.com
gstatic.com
wordpress.org
api.wordpress.org
downloads.wordpress.org
cloudflare.com
cdnjs.cloudflare.com
cdn.jsdelivr.net
unpkg.com
localhost
127.0.0.1",

        /**
         * blacklist
         */
        'blocked_keywords' => "facebook
twitter
x.com
instagram
youtube
doubleclick
googlesyndication
googletagmanager
google-analytics
hotjar
tiktok
vimeo
stripe
paypal",
    ];

    public function __construct() {

        add_action(
            'admin_menu',
            [$this, 'add_admin_menu']
        );

        add_action(
            'admin_init',
            [$this, 'register_settings']
        );

        /**
         * settings
         */
        $settings = $this->get_settings();

        /**
         * whitelist
         */
        $this->allowed_hosts = array_filter(
            array_map(
                'trim',
                explode(
                    "\n",
                    $settings['allowed_hosts']
                )
            )
        );

        /**
         * blacklist
         */
        $this->blocked_keywords = array_filter(
            array_map(
                'trim',
                explode(
                    "\n",
                    $settings['blocked_keywords']
                )
            )
        );

        /**
         * firewall
         */
        if (!empty($settings['enable_blocking'])) {

            add_filter(
                'pre_http_request',
                [$this, 'block_external_requests'],
                10,
                3
            );
        }

        /**
         * timeout
         */
        if (!empty($settings['reduce_timeout'])) {
            $this->reduce_timeout();
        }

        /**
         * emoji
         */
        if (!empty($settings['disable_emojis'])) {
            $this->disable_emojis();
        }

        /**
         * gravatar
         */
        if (!empty($settings['disable_gravatar'])) {
            $this->disable_gravatar();
        }

        /**
         * oembed
         */
        if (!empty($settings['disable_oembed'])) {
            $this->disable_oembed();
        }

        /**
         * clean html
         */
        if (!empty($settings['clean_output'])) {

            add_action(
                'template_redirect',
                [$this, 'start_buffer']
            );
        }
    }

    /**
     * settings
     */
    private function get_settings() {

        return wp_parse_args(
            get_option($this->option_name, []),
            $this->default_settings
        );
    }

    /**
     * admin menu
     */
    public function add_admin_menu() {

        add_menu_page(
            'ایران پرو',
            'ایران پرو',
            'manage_options',
            'block-external-iran',
            [$this, 'settings_page'],
            'dashicons-shield-alt',
            81
        );
    }

    /**
     * register
     */
    public function register_settings() {

        register_setting(
            $this->option_name,
            $this->option_name
        );
    }

    /**
     * timeout
     */
    public function reduce_timeout() {

        add_filter(
            'http_request_timeout',
            function () {
                return 5;
            }
        );

        add_filter(
            'http_request_args',
            function ($args) {

                $args['timeout'] = 5;

                $args['connect_timeout'] = 3;

                return $args;
            }
        );
    }

    /**
     * emoji
     */
    public function disable_emojis() {

        remove_action(
            'wp_head',
            'print_emoji_detection_script',
            7
        );

        remove_action(
            'admin_print_scripts',
            'print_emoji_detection_script'
        );

        remove_action(
            'wp_print_styles',
            'print_emoji_styles'
        );

        remove_action(
            'admin_print_styles',
            'print_emoji_styles'
        );

        add_filter(
            'emoji_svg_url',
            '__return_false'
        );
    }

    /**
     * gravatar
     */
    public function disable_gravatar() {

        add_filter(
            'get_avatar',
            function ($avatar, $id_or_email, $size) {

                return '<div style="
                    width:' . (int)$size . 'px;
                    height:' . (int)$size . 'px;
                    border-radius:50%;
                    background:#e2e8f0;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                    color:#475569;
                    font-size:12px;
                ">User</div>';

            },
            10,
            3
        );
    }

    /**
     * oembed
     */
    public function disable_oembed() {

        remove_action(
            'wp_head',
            'wp_oembed_add_discovery_links'
        );

        remove_action(
            'wp_head',
            'wp_oembed_add_host_js'
        );

        add_filter(
            'embed_oembed_discover',
            '__return_false'
        );
    }

    /**
     * output buffer
     */
    public function start_buffer() {

        if (
            !is_admin() &&
            !wp_doing_ajax() &&
            !wp_doing_cron()
        ) {

            ob_start([$this, 'clean_output']);
        }
    }

    /**
     * clean html
     */
    public function clean_output($html) {

        if (empty($html)) {
            return $html;
        }

        /**
         * remove google fonts
         */
        $html = preg_replace(
            '/<link[^>]*fonts\.googleapis\.com[^>]*>/i',
            '',
            $html
        );

        return $html;
    }

    /**
     * firewall
     */
    public function block_external_requests(
        $preempt,
        $args,
        $url
    ) {

        $host = parse_url(
            $url,
            PHP_URL_HOST
        );

        if (!$host) {
            return $preempt;
        }

        $host = strtolower($host);

        /**
         * ir domains
         */
        if (
            preg_match(
                '/\.ir$/i',
                $host
            )
        ) {

            return $preempt;
        }

        /**
         * whitelist
         */
        foreach ($this->allowed_hosts as $allowed) {

            if (
                $host === $allowed ||
                str_ends_with(
                    $host,
                    '.' . $allowed
                )
            ) {

                return $preempt;
            }
        }

        /**
         * blacklist
         */
        foreach ($this->blocked_keywords as $keyword) {

            if (
                stripos(
                    $host,
                    $keyword
                ) !== false
            ) {

                $this->log_request(
                    $url,
                    $host
                );

                return new WP_Error(
                    'blocked_request',
                    'Blocked by Iran Pro Firewall'
                );
            }
        }

        return $preempt;
    }

    /**
     * logs
     */
    private function log_request(
        $url,
        $host
    ) {

        $settings = $this->get_settings();

        if (
            empty($settings['enable_logging'])
        ) {

            return;
        }

        $logs = get_option(
            $this->log_option,
            []
        );

        $logs[] = [

            'time' => current_time('mysql'),
            'host' => $host,
            'url'  => $url,
        ];

        /**
         * limit
         */
        if (count($logs) > 300) {

            $logs = array_slice(
                $logs,
                -300
            );
        }

        update_option(
            $this->log_option,
            $logs
        );
    }

    /**
     * admin page
     */
    public function settings_page() {

        $settings = $this->get_settings();

        $logs = array_reverse(
            get_option(
                $this->log_option,
                []
            )
        );

        ?>

        <style>

           @font-face{
            font-family:'IRANSans';
            src:url('../fonts/iransans/IRANSansWeb.woff2') format('woff2');
        }


            .ber-wrap *{
                font-family:'IRANSans',Tahoma !important;
            }

            .ber-wrap{
                direction:rtl;
                max-width:1300px;
                margin:25px auto;
            }

            .ber-header{
                background:linear-gradient(135deg,#020617,#0f172a);
                border-radius:30px;
                padding:40px;
                color:#fff;
                margin-bottom:25px;
                box-shadow:0 20px 50px rgba(0,0,0,.2);
                color:#fff;
            }

            .ber-header h1{
                margin:0;
                font-size:38px;
                font-weight:900;
				 color:#fff;
            }

            .ber-header p{
                margin-top:12px;
                opacity:.8;
                font-size:15px;
            }

            .ber-grid{
                display:grid;
                grid-template-columns:1fr 1fr;
                gap:25px;
            }

            @media(max-width:950px){

                .ber-grid{
                    grid-template-columns:1fr;
                }
            }

            .ber-card{
                background:#fff;
                border-radius:24px;
                padding:25px;
                box-shadow:0 10px 35px rgba(0,0,0,.06);
                border:1px solid #e2e8f0;
            }

            .ber-card h2{
                margin-top:0;
                margin-bottom:25px;
                font-size:24px;
                color:#0f172a;
            }

            .ber-setting{
                display:flex;
                align-items:center;
                justify-content:space-between;
                padding:18px 0;
                border-bottom:1px solid #f1f5f9;
            }

            .ber-setting:last-child{
                border-bottom:none;
            }

            .ber-title{
                font-size:15px;
                font-weight:700;
                color:#0f172a;
            }

            .ber-desc{
                margin-top:6px;
                font-size:13px;
                color:#64748b;
            }

            .ber-switch{
                position:relative;
                width:58px;
                height:32px;
            }

            .ber-switch input{
                opacity:0;
                width:0;
                height:0;
            }

            .ber-slider{
                position:absolute;
                inset:0;
                background:#cbd5e1;
                border-radius:999px;
                transition:.3s;
                cursor:pointer;
            }

            .ber-slider:before{
                content:"";
                position:absolute;
                width:24px;
                height:24px;
                right:4px;
                top:4px;
                background:#fff;
                border-radius:50%;
                transition:.3s;
            }

            .ber-switch input:checked + .ber-slider{
                background:#10b981;
            }

            .ber-switch input:checked + .ber-slider:before{
                transform:translateX(-26px);
            }

            .ber-textarea{
                width:100%;
                min-height:220px;
                border:1px solid #cbd5e1;
                border-radius:18px;
                padding:15px;
                resize:vertical;
                margin-top:12px;
                font-size:14px;
                background:#f8fafc;
                direction:ltr;
            }

            .ber-btn{
                background:#0f172a !important;
                border:none !important;
                border-radius:16px !important;
                padding:12px 30px !important;
                font-size:15px !important;
                font-weight:700 !important;
                margin-top:25px !important;
            }

            .ber-status{
                display:flex;
                align-items:center;
                justify-content:space-between;
                padding:15px 0;
                border-bottom:1px solid #f1f5f9;
            }

            .ber-badge{
                padding:8px 15px;
                border-radius:999px;
                font-size:12px;
                font-weight:700;
            }

            .green{
                background:#dcfce7;
                color:#166534;
            }

            .red{
                background:#fee2e2;
                color:#991b1b;
            }

            .blue{
                background:#dbeafe;
                color:#1d4ed8;
            }

            .ber-table{
                width:100%;
                border-collapse:collapse;
            }

            .ber-table thead{
                background:#0f172a;
                color:#fff;
            }

            .ber-table th,
            .ber-table td{
                padding:15px;
                text-align:right;
                border-bottom:1px solid #e2e8f0;
                font-size:13px;
            }

            .ber-table tbody tr:hover{
                background:#f8fafc;
            }

        </style>

        <div class="wrap ber-wrap">

            <div class="ber-header">

                <h1>🚀 ایران پرو Ultimate</h1>

                <p>
                    فایروال حرفه‌ای وردپرس + کنترل کامل درخواست‌های خارجی
                </p>

            </div>

            <form method="post" action="options.php">

                <?php settings_fields($this->option_name); ?>

                <div class="ber-grid">

                    <div class="ber-card">

                        <h2>⚙️ تنظیمات اصلی</h2>

                        <?php foreach ($this->default_settings as $key => $value): ?>

                            <?php
                            if (
                                $key === 'allowed_hosts' ||
                                $key === 'blocked_keywords'
                            ) {
                                continue;
                            }
                            ?>

                            <div class="ber-setting">

                                <div>

                                    <div class="ber-title">

                                        <?php echo esc_html(
                                            $this->label($key)
                                        ); ?>

                                    </div>

                                    <div class="ber-desc">

                                        <?php echo esc_html(
                                            $this->desc($key)
                                        ); ?>

                                    </div>

                                </div>

                                <label class="ber-switch">

                                    <input
                                        type="checkbox"
                                        name="<?php echo esc_attr($this->option_name); ?>[<?php echo esc_attr($key); ?>]"
                                        value="1"
                                        <?php checked(!empty($settings[$key])); ?>
                                    >

                                    <span class="ber-slider"></span>

                                </label>

                            </div>

                        <?php endforeach; ?>

                    </div>

                    <div class="ber-card">

                        <h2>📊 وضعیت سیستم</h2>

                        <div class="ber-status">

                            <div>وضعیت فایروال</div>

                            <div class="ber-badge green">

                                <?php echo !empty($settings['enable_blocking']) ? 'فعال' : 'غیرفعال'; ?>

                            </div>

                        </div>

                        <div class="ber-status">

                            <div>دامنه‌های مجاز</div>

                            <div class="ber-badge blue">

                                <?php echo count($this->allowed_hosts); ?>

                            </div>

                        </div>

                        <div class="ber-status">

                            <div>دامنه‌های بلاک</div>

                            <div class="ber-badge red">

                                <?php echo count($this->blocked_keywords); ?>

                            </div>

                        </div>

                        <div class="ber-status">

                            <div>تعداد لاگ</div>

                            <div class="ber-badge blue">

                                <?php echo count($logs); ?>

                            </div>

                        </div>

                    </div>

                </div>

                <div class="ber-grid" style="margin-top:25px;">

                    <div class="ber-card">

                        <h2>✅ دامنه‌های مجاز</h2>

                        <p>
                            هر دامنه در یک خط
                        </p>

                        <textarea
                            class="ber-textarea"
                            name="<?php echo esc_attr($this->option_name); ?>[allowed_hosts]"
                        ><?php echo esc_textarea($settings['allowed_hosts']); ?></textarea>

                    </div>

                    <div class="ber-card">

                        <h2>⛔ دامنه‌های بلاک</h2>

                        <p>
                            هر دامنه در یک خط
                        </p>

                        <textarea
                            class="ber-textarea"
                            name="<?php echo esc_attr($this->option_name); ?>[blocked_keywords]"
                        ><?php echo esc_textarea($settings['blocked_keywords']); ?></textarea>

                    </div>

                </div>

                <p>

                    <button
                        type="submit"
                        class="button button-primary ber-btn"
                    >
                        💾 ذخیره تنظیمات
                    </button>

                </p>

            </form>

            <div class="ber-card" style="margin-top:25px;">

                <h2>📋 آخرین درخواست‌های بلاک شده</h2>

                <table class="ber-table">

                    <thead>

                        <tr>

                            <th>زمان</th>
                            <th>دامنه</th>
                            <th>آدرس</th>

                        </tr>

                    </thead>

                    <tbody>

                    <?php if (empty($logs)): ?>

                        <tr>

                            <td colspan="3">

                                لاگی ثبت نشده است

                            </td>

                        </tr>

                    <?php else: ?>

                        <?php foreach ($logs as $log): ?>

                            <tr>

                                <td>

                                    <?php echo esc_html($log['time']); ?>

                                </td>

                                <td>

                                    <strong>

                                        <?php echo esc_html($log['host']); ?>

                                    </strong>

                                </td>

                                <td>

                                    <?php echo esc_html($log['url']); ?>

                                </td>

                            </tr>

                        <?php endforeach; ?>

                    <?php endif; ?>

                    </tbody>

                </table>

            </div>

        </div>

        <?php
    }

    /**
     * labels
     */
    private function label($key) {

        $labels = [

            'enable_blocking'  => 'فعال‌سازی فایروال',
            'reduce_timeout'   => 'کاهش Timeout',
            'disable_emojis'   => 'غیرفعال‌سازی Emoji',
            'disable_gravatar' => 'غیرفعال‌سازی Gravatar',
            'disable_oembed'   => 'غیرفعال‌سازی oEmbed',
            'clean_output'     => 'پاکسازی HTML',
            'enable_logging'   => 'ثبت لاگ',
        ];

        return $labels[$key] ?? $key;
    }

    /**
     * descriptions
     */
    private function desc($key) {

        $desc = [

            'enable_blocking' =>
                'مسدودسازی درخواست‌های خارجی',

            'reduce_timeout' =>
                'کاهش زمان انتظار درخواست‌ها',

            'disable_emojis' =>
                'حذف اسکریپت Emoji وردپرس',

            'disable_gravatar' =>
                'جلوگیری از درخواست به Gravatar',

            'disable_oembed' =>
                'غیرفعال‌سازی oEmbed',

            'clean_output' =>
                'پاکسازی HTML خروجی',

            'enable_logging' =>
                'ثبت درخواست‌های بلاک شده',
        ];

        return $desc[$key] ?? '';
    }
}

new Block_External_Requests_Iran_Pro();
