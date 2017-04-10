
JSON Web Tokens фильтр
jwt.io

Настройка фильтра

копируем pubcookie-1.0-SNAPSHOT.jar и зависимости commons-io-2.4.jar, jackson-core-2.4.2.jar, javax.servlet-api-3.1.0.jar, jackson-annotations-2.4.0.jar, jackson-databind-2.4.2.jar, jjwt-0.6.0.jar, slf4j-api-1.7.2.jar в WEB_INF/lib приложения. В web.xml добавляем фильтр

```
<filter>
    <filter-name>jwt-filter</filter-name>
    <filter-class>org.bmstu.JWTFilter</filter-class>
    <!-- pubcookie cookie name -->
    <init-param>
        <param-name>cookieName</param-name>
        <param-value>__portal3_login</param-value>
    </init-param>
    <!-- auth page redirect address -->
    <init-param>
        <param-name>loginPage</param-name>
        <param-value>http://portal3.eu.bmstu.ru/portal3/login/internal</param-value>
    </init-param>
    <!-- space separated trusted hosts -->
    <init-param>
        <param-name>trustedHosts</param-name>
        <param-value>localhost 127.0.0.1</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>jwt-filter</filter-name>
    <url-pattern>*</url-pattern>
</filter-mapping>
```




