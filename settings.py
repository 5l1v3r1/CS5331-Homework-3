DOWNLOADER_MIDDLEWARES = {
  'scrapy_splash.SplashCookiesMiddleware': 723,
  'scrapy_splash.SplashMiddleware': 725,
  'scrapy.downloadermiddlewares.httpcompression.HttpCompressionMiddleware': 810,
},

SPLASH_URL = 'http://192.168.59.103:8050',

DOWNLOAD_DELAY = 1000
