import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{EngineContext, EngineConfig}
import io.shiftleft.codepropertygraph.generated.nodes.AstNode

@main def exec(cpgFile: String, rulesFile: String, outFile: String, maxFlows: Int, maxDepth: Int) = {
  importCpg(cpgFile)
  if (!cpg.metaData.overlays.l.flatten.contains("dataflowOss")) run.ossdataflow
  given EngineContext = EngineContext(config = EngineConfig(maxCallDepth = maxDepth))
  val rules = ujson.read(java.nio.file.Files.readString(java.nio.file.Paths.get(rulesFile))).arr
  var sourceCount = 0
  var sinkCount = 0
  val flows = scala.collection.mutable.ArrayBuffer.empty[ujson.Value]
  var truncated = false
  def matching(pattern: String, name: String, fullName: String): Boolean = {
    val p = java.util.regex.Pattern.compile(pattern)
    p.matcher(name).matches || p.matcher(fullName).matches
  }
  def node(n: AstNode): ujson.Value = {
    val method = n.start.inAst.isMethod.headOption
    ujson.Obj("id" -> n.id.toString, "label" -> n.label,
      "code" -> n.code.take(2000), "code_truncated" -> (n.code.length > 2000),
      "filename" -> method.map(_.filename).getOrElse(""),
      "method_id" -> method.map(_.id.toString).getOrElse(""),
      "line" -> n.lineNumber.map(ujson.Num(_)).getOrElse(ujson.Null),
      "column" -> n.columnNumber.map(ujson.Num(_)).getOrElse(ujson.Null))
  }
  for (rule <- rules) {
    val s = rule("source")
    val sourcePattern = s("method").str
    val sources: List[AstNode] = s("kind").str match {
      case "parameter" => cpg.method.filter(m => matching(sourcePattern,m.name,m.fullName)).parameter.filter(p => p.index > 0 && (s("index").num.toInt == 0 || p.index == s("index").num.toInt)).take(10001).toList
      case "call_return" => cpg.call.filter(c => matching(sourcePattern,c.name,c.methodFullName)).filter(c => java.util.regex.Pattern.matches(s("code_pattern").str,c.code)).take(10001).toList
    }
    val t = rule("sink")
    val sinks = cpg.call.filter(c => matching(t("method").str,c.name,c.methodFullName)).argument(t("argument_index").num.toInt).take(10001).toList
    require(sources.size <= 10000 && sinks.size <= 10000, "selection_budget_exceeded")
    sourceCount += sources.size
    sinkCount += sinks.size
    val remaining = maxFlows - flows.size
    val paths = sinks.iterator.reachableByFlows(sources.iterator).take(remaining + 1).toList
    if (paths.size > remaining) truncated = true
    paths.take(remaining).foreach { path =>
      require(path.elements.nonEmpty && path.elements.size <= 256, "trace_budget_exceeded")
      flows += ujson.Obj("rule_id" -> rule("id"), "nodes" -> ujson.Arr.from(path.elements.map(node)))
    }
  }
  val result = ujson.Obj("source_count" -> sourceCount, "sink_count" -> sinkCount, "truncated" -> truncated, "flows" -> ujson.Arr.from(flows))
  val encoded = ujson.write(result)
  require(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 16777216, "report_budget_exceeded")
  java.nio.file.Files.writeString(java.nio.file.Paths.get(outFile), encoded)
}
