import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.xml.parsers.DocumentBuilder;
import org.apache.ibatis.session.SqlSession;
import org.hibernate.Session;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import freemarker.template.Configuration;
import org.thymeleaf.spring5.SpringTemplateEngine;

final class SinkFixture {
  Object deserialize(ObjectInputStream input) throws Exception {
    return input.readObject();
  }

  Object decode(InputStream input) throws Exception {
    return new XMLDecoder(input).readObject();
  }

  Object lookup(InitialContext context, String name) throws Exception {
    return context.lookup(name);
  }

  Object lookupInterface(Context context, String name) throws Exception {
    return context.lookup(name);
  }

  void xml(DocumentBuilder parser, InputStream input) throws Exception {
    parser.parse(input);
  }

  void sql(Statement statement, String query) throws Exception {
    statement.executeQuery(query);
  }

  void parameterized(PreparedStatement statement) throws Exception {
    statement.executeQuery();
  }

  Object fixedDecoder() throws Exception {
    byte[] bytes = new byte[0];
    return new XMLDecoder(new ByteArrayInputStream(bytes)).readObject();
  }

  void command(String command, Runtime runtime) throws Exception {
    runtime.exec(command);
  }

  Object expression(String expression, SpelExpressionParser parser) {
    return parser.parseExpression(expression);
  }

  Object mybatis(String statement, Object parameter, SqlSession session) {
    return session.selectOne(statement, parameter);
  }

  Object hibernate(String query, Session session) {
    return session.createQuery(query);
  }

  Object template(String name, Configuration configuration) throws Exception {
    return configuration.getTemplate(name);
  }

  void thymeleaf(String name, Object context, SpringTemplateEngine engine) {
    engine.process(name, context, null);
  }
}
