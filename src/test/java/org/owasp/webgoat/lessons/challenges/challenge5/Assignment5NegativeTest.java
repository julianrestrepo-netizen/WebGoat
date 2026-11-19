package org.owasp.webgoat.lessons.challenges.challenge5;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/** Pruebas negativas sobre POST /challenge/5 (Assignment5.login). */
class Assignment5NegativeTest extends LessonTest {

  @BeforeEach
  void conSeguridad() {
    // LessonTest crea el MockMvc sin filtros de seguridad; aqui se activan.
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).apply(springSecurity()).build();
  }

  // 1) AUTENTICACION: sin sesion la peticion se rechaza.
  @Test
  void sinSesionEsRechazada() throws Exception {
    mockMvc
        .perform(
            post("/challenge/5")
                .with(anonymous())
                .param("username_login", "Larry")
                .param("password_login", "x"))
        .andExpect(
            result -> {
              int s = result.getResponse().getStatus();
              assertTrue(s == 401 || s == 302, "Estado inesperado: " + s);
            });
  }

  // 2) AUTORIZACION: un usuario sin rol WEBGOAT_ADMIN no accede a /service/admin.
  @Test
  void usuarioSinRolNoAccedeAAdmin() throws Exception {
    mockMvc.perform(get("/service/admin/cualquiera")).andExpect(status().isForbidden());
  }

  // 3) VALIDACION DE ENTRADAS: entradas maliciosas o vacias no resuelven el reto.
  @ParameterizedTest
  @ValueSource(strings = {"' OR '1'='1", "' OR 1=1 --", "<script>alert(1)</script>", ""})
  void entradasMaliciosasSonRechazadas(String password) throws Exception {
    mockMvc
        .perform(
            post("/challenge/5").param("username_login", "Larry").param("password_login", password))
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  // 4) MANEJO DE ERRORES: peticion mal formada -> 400 sin detalles internos.
  @Test
  void errorNoExponeDetalles() throws Exception {
    mockMvc
        .perform(post("/challenge/5").param("username_login", "Larry"))
        .andExpect(status().isBadRequest())
        .andExpect(content().string(not(containsString("Exception"))))
        .andExpect(content().string(not(containsString("org.springframework"))));
  }
}
