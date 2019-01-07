package authrest;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import javax.ws.rs.NameBinding;

/**
 * ao anotar um filtro com esta anotacao, somente alguns metodos passam pelo
 * filtro
 */
@NameBinding
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Autenticado {

    String[] value() default "";
}
