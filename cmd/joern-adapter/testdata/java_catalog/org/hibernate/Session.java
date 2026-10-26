package org.hibernate;

public interface Session {
  Object createQuery(String queryString);
}
