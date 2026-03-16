<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>正在重定向到 {{ site.title }}...</title>
  <meta http-equiv="refresh" content="0; url={{ site.baseurl }}/">
  <script>
    window.location.href = "{{ site.baseurl }}/";
  </script>
</head>
<body>
  <p>正在重定向到 <a href="{{ site.baseurl }}/">{{ site.title }}</a>...</p>
</body>
</html>
