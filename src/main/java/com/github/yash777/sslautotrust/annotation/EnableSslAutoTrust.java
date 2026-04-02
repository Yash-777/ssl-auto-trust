package com.github.yash777.sslautotrust.annotation;

import com.github.yash777.sslautotrust.autoconfigure.SslAutoTrustAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * EnableSslAutoTrust
 *
 * <p>Optional activation annotation for the SSL Auto-Trust starter.
 * When placed on any {@code @Configuration} or {@code @SpringBootApplication}
 * class it imports {@link SslAutoTrustAutoConfiguration} directly — this is
 * the annotation-based alternative to setting
 * {@code ssl.auto-trust.enabled=true} in {@code application.properties}.
 *
 * <h3>Behaviour</h3>
 * <ul>
 *   <li>If {@code ssl.auto-trust.enabled=false} is set in properties, the
 *       property wins and the configuration is suppressed even if the
 *       annotation is present. Remove the property or set it to {@code true}
 *       when using the annotation.</li>
 *   <li>The early JVM-patch listener ({@link com.github.yash777.sslautotrust.initializer.SslAutoTrustInitializer})
 *       is auto-registered via {@code spring.factories} — no additional code needed.</li>
 * </ul>
 *
 * <h3>Usage — Option A: on main class</h3>
 * <pre>{@code
 * @SpringBootApplication
 * @EnableSslAutoTrust
 * public class MyApplication {
 *     public static void main(String[] args) {
 *         SpringApplication.run(MyApplication.class, args);
 *     }
 * }
 * }</pre>
 *
 * <h3>Usage — Option B: on a @Configuration class</h3>
 * <pre>{@code
 * @Configuration
 * @EnableSslAutoTrust
 * public class MyHttpConfig {
 *     // SslAutoTrustAutoConfiguration imported automatically
 * }
 * }</pre>
 *
 * <h3>Mechanism vs property</h3>
 * <table border="1" cellpadding="4">
 *   <tr><th>Mechanism</th><th>Controls early listener?</th><th>Controls @Bean?</th></tr>
 *   <tr><td>{@code ssl.auto-trust.enabled=true}</td><td>Yes</td><td>Yes</td></tr>
 *   <tr><td>{@code @EnableSslAutoTrust}</td><td>Via spring.factories</td><td>Yes (@Import)</td></tr>
 * </table>
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(SslAutoTrustAutoConfiguration.class)
public @interface EnableSslAutoTrust {
}
