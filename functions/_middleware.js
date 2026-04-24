if (!SITE_PASSWORD) {
  return next(); // 直接放行所有请求
}
