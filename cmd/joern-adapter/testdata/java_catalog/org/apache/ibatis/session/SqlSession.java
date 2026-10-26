package org.apache.ibatis.session;

public interface SqlSession {
  Object selectOne(String statement, Object parameter);
}
