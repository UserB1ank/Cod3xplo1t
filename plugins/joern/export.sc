@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  val files = cpg.file.take(20001).map(f => ujson.Obj("id" -> f.id.toString, "name" -> f.name)).toList
  val methods = cpg.method.take(100001).map(m => ujson.Obj("id" -> m.id.toString, "name" -> m.name, "full_name" -> m.fullName, "signature" -> m.signature, "filename" -> m.filename, "external" -> m.isExternal, "line" -> m.lineNumber.map(ujson.Num(_)).getOrElse(ujson.Null), "column" -> m.columnNumber.map(ujson.Num(_)).getOrElse(ujson.Null))).toList
  val calls = cpg.call.filterNot(_.name.startsWith("<operator>")).take(100001).map(c => ujson.Obj("id" -> c.id.toString, "name" -> c.name, "method_full_name" -> c.methodFullName, "filename" -> c.method.filename, "line" -> c.lineNumber.map(ujson.Num(_)).getOrElse(ujson.Null), "column" -> c.columnNumber.map(ujson.Num(_)).getOrElse(ujson.Null), "caller" -> c.method.id.toString, "callees" -> ujson.Arr.from(c.callee.map(m => ujson.Obj("id" -> m.id.toString,"external" -> m.isExternal)).toList))).toList
  require(files.size <= 20000 && methods.size <= 100000 && calls.size <= 100000, "export_budget_exceeded")
  java.nio.file.Files.writeString(java.nio.file.Paths.get(outFile), ujson.write(ujson.Obj("files" -> ujson.Arr.from(files), "methods" -> ujson.Arr.from(methods), "calls" -> ujson.Arr.from(calls))))
}
