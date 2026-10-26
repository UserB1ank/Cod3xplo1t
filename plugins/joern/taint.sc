import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{EngineContext, EngineConfig}
import io.shiftleft.codepropertygraph.generated.nodes.AstNode

@main def exec(cpgFile: String, rulesFile: String, catalogFile: String, outFile: String, maxFlows: Int, maxDepth: Int) = {
  importCpg(cpgFile)
  if (!cpg.metaData.overlays.l.flatten.contains("dataflowOss")) run.ossdataflow
  given EngineContext = EngineContext(config = EngineConfig(maxCallDepth = maxDepth))
  val rules = ujson.read(java.nio.file.Files.readString(java.nio.file.Paths.get(rulesFile))).arr
  val catalog = ujson.read(java.nio.file.Files.readString(java.nio.file.Paths.get(catalogFile))).obj("entries").arr
  var sourceCount = 0
  var sinkCount = 0
  val flows = scala.collection.mutable.ArrayBuffer.empty[ujson.Value]
  val sinkInventory = scala.collection.mutable.ArrayBuffer.empty[ujson.Value]
  val partitionLedger = scala.collection.mutable.ArrayBuffer.empty[ujson.Value]
  val catalogCalls = scala.collection.mutable.ArrayBuffer.empty[(String, io.shiftleft.codepropertygraph.generated.nodes.Call, List[Int])]
  var truncated = false
  var selectionTruncated = false
  var flowTruncated = false
  var catalogSelectionTruncated = false
  var catalogFlowTruncated = false
  def matching(p: java.util.regex.Pattern, name: String, fullName: String): Boolean = p.matcher(name).matches || p.matcher(fullName).matches
  val catalogRules = catalog.map { entry =>
    val matchType = entry("match")("match_type").str
    val receiver = entry("match")("receiver_type").str
    val method = entry("match")("method").str
    if (matchType == "regex") {
      (entry, Option(if (receiver.nonEmpty) java.util.regex.Pattern.compile(receiver) else null), Option(java.util.regex.Pattern.compile(method)))
    } else {
      (entry, None, None)
    }
  }
  def catalogMatches(c: io.shiftleft.codepropertygraph.generated.nodes.Call, item: (ujson.Value, Option[java.util.regex.Pattern], Option[java.util.regex.Pattern])): Boolean = {
    item match {
      case (entry, receiverPattern, methodPattern) =>
        val matchType = entry("match")("match_type").str
        val receiver = entry("match")("receiver_type").str
        val method = entry("match")("method").str
        if (matchType == "exact") {
          val target = receiver + "." + method
          c.methodFullName == target || c.methodFullName.startsWith(target + ":")
        } else {
          val receiverMatches = receiverPattern.forall(_.matcher(c.methodFullName).find())
          val methodMatches = methodPattern.exists(p => p.matcher(c.name).matches || p.matcher(c.methodFullName).matches)
          receiverMatches && methodMatches
        }
    }
  }
  def catalogIDs(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Seq[String] =
    catalogRules.iterator.filter(item => catalogMatches(c, item)).map(_._1("id").str).toSeq
  def sourceCandidates(s: ujson.Value): Iterator[AstNode] = {
    val sourcePattern = java.util.regex.Pattern.compile(s("method").str)
    val codePattern = java.util.regex.Pattern.compile(s("code_pattern").str)
    s("kind").str match {
      case "parameter" => cpg.method.filter(m => matching(sourcePattern,m.name,m.fullName)).parameter.filter(p => p.index > 0 && (s("index").num.toInt == 0 || p.index == s("index").num.toInt))
      case "call_return" => cpg.call.filter(c => matching(sourcePattern,c.name,c.methodFullName)).filter(c => codePattern.matcher(c.code).matches)
    }
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
  for (item <- catalogRules) {
    var matched = 0
    val matches = cpg.call.filter(c => catalogMatches(c, item)).filter { _ => matched += 1; matched <= 10000 }.toList
    if (matched > matches.size) { catalogSelectionTruncated = true; truncated = true }
    matches.foreach { call =>
      val entry = item._1
      val dangerous = entry("dangerous_arguments").arr.map(_.num.toInt).toList
      catalogCalls += ((entry("category").str, call, dangerous))
      sinkInventory += ujson.Obj(
        "rule_id" -> entry("id").str,
        "category" -> entry("category").str,
        "method_full_name" -> call.methodFullName,
        "dangerous_arguments" -> entry("dangerous_arguments"),
        "priority" -> entry("priority").num,
        "evidence" -> entry("evidence").str,
        "limitations" -> entry("limitations"),
        "node" -> node(call)
      )
    }
  }
  val catalogSources = rules.iterator.flatMap(rule => sourceCandidates(rule("source"))).toList.distinctBy(_.id)
  val categories = catalogCalls.groupBy(_._1).toList.sortBy { case (category, values) =>
    val priorities = values.map { case (_, call, _) =>
      catalogRules.iterator.filter(item => item._1("category").str == category && catalogMatches(call, item)).map(_._1("priority").num).toSeq.maxOption.getOrElse(0.0)
    }
    (-priorities.maxOption.getOrElse(0.0), category)
  }
  val catalogBudget = maxFlows * 4 / 5
  for (((category, values), index) <- categories.zipWithIndex) {
    val remainingCategories = categories.size - index
    val remainingInBudget = math.max(0, catalogBudget - flows.size)
    val share = if (remainingInBudget > 0) math.max(1, remainingInBudget / remainingCategories) else 0
    val remaining = math.min(share, math.max(0, maxFlows - flows.size))
    val sinks = values.flatMap { case (_, call, dangerous) =>
      val args = dangerous.flatMap(index => call.argument(index + 1))
      if (args.nonEmpty) args else List(call)
    }.toList.distinctBy(_.id)
    val paths = if (remaining > 0) sinks.iterator.reachableByFlows(catalogSources.iterator).take(remaining + 1).toList else List.empty
    if (remaining == 0 && sinks.nonEmpty) { catalogFlowTruncated = true; truncated = true }
    if (paths.size > remaining) { catalogFlowTruncated = true; truncated = true }
    val priorities = values.flatMap { case (_, call, _) =>
      catalogRules.iterator.filter(item => item._1("category").str == category && catalogMatches(call, item)).map(_._1("priority").num)
    }
    val ruleIDs = values.flatMap { case (_, call, _) =>
      catalogRules.iterator.filter(item => catalogMatches(call, item)).map(_._1("id").str)
    }.distinct.sorted
    val status = if (remaining == 0 && sinks.nonEmpty) "pending" else if (paths.size > remaining) "truncated" else "complete"
    partitionLedger += ujson.Obj(
      "id" -> ("catalog:" + category),
      "kind" -> "catalog",
      "rule_ids" -> ujson.Arr.from(ruleIDs),
      "priority" -> priorities.maxOption.getOrElse(0.0),
      "candidate_sinks" -> sinks.size,
      "flow_budget" -> remaining,
      "flows" -> math.min(paths.size, remaining),
      "status" -> status
    )
    paths.take(remaining).foreach { path =>
      require(path.elements.nonEmpty && path.elements.size <= 256, "trace_budget_exceeded")
      val sinkCall = path.elements.last.start.inAst.isCall.headOption
      val catalogIDsAtSink = sinkCall.map(catalogIDs).getOrElse(Seq.empty)
      flows += ujson.Obj(
        "rule_id" -> ("catalog:" + category),
        "sink_call_id" -> sinkCall.map(_.id.toString).getOrElse(""),
        "sink_catalog_ids" -> ujson.Arr.from(catalogIDsAtSink),
        "nodes" -> ujson.Arr.from(path.elements.map(node))
      )
    }
  }
  for ((rule, ruleIndex) <- rules.zipWithIndex) {
    val s = rule("source")
    val candidates = sourceCandidates(s)
    var matchedSources = 0
    val sources = candidates.filter { _ => matchedSources += 1; matchedSources <= 10000 }.toList
    val t = rule("sink")
    val sinkPattern = java.util.regex.Pattern.compile(t("method").str)
    var matchedSinks = 0
    val sinks = cpg.call.filter(c => matching(sinkPattern,c.name,c.methodFullName)).argument(t("argument_index").num.toInt).filter { _ => matchedSinks += 1; matchedSinks <= 10000 }.toList
    if (matchedSources > sources.size || matchedSinks > sinks.size) { selectionTruncated = true; truncated = true }
    sourceCount += matchedSources
    sinkCount += matchedSinks
    val remainingRules = rules.size - ruleIndex
    val remainingTotal = math.max(0, maxFlows - flows.size)
    val share = if (remainingTotal > 0) math.max(1, remainingTotal / remainingRules) else 0
    val remaining = math.min(share, remainingTotal)
    val paths = if (remaining > 0) sinks.iterator.reachableByFlows(sources.iterator).take(remaining + 1).toList else List.empty
    if (remaining == 0 && sinks.nonEmpty) { truncated = true; flowTruncated = true }
    if (paths.size > remaining) { truncated = true; flowTruncated = true }
    val status = if (remaining == 0 && sinks.nonEmpty) "pending" else if (paths.size > remaining) "truncated" else "complete"
    partitionLedger += ujson.Obj(
      "id" -> ("fallback:" + rule("id").str),
      "kind" -> "fallback",
      "rule_ids" -> ujson.Arr(rule("id")),
      "priority" -> 0.0,
      "candidate_sinks" -> sinks.size,
      "flow_budget" -> remaining,
      "flows" -> math.min(paths.size, remaining),
      "status" -> status
    )
    paths.take(remaining).foreach { path =>
      require(path.elements.nonEmpty && path.elements.size <= 256, "trace_budget_exceeded")
      val sinkCall = path.elements.last.start.inAst.isCall.headOption
      val catalogIDsAtSink = sinkCall.map(catalogIDs).getOrElse(Seq.empty)
      flows += ujson.Obj(
        "rule_id" -> rule("id"),
        "sink_call_id" -> sinkCall.map(_.id.toString).getOrElse(""),
        "sink_catalog_ids" -> ujson.Arr.from(catalogIDsAtSink),
        "nodes" -> ujson.Arr.from(path.elements.map(node))
      )
    }
  }
  if (flows.size >= maxFlows) { flowTruncated = true; truncated = true }
  val result = ujson.Obj(
    "selection_truncated" -> selectionTruncated,
    "flow_truncated" -> flowTruncated,
    "catalog_selection_truncated" -> catalogSelectionTruncated,
    "catalog_flow_truncated" -> catalogFlowTruncated,
    "source_count" -> sourceCount,
    "sink_count" -> sinkCount,
    "truncated" -> truncated,
    "sink_inventory" -> ujson.Arr.from(sinkInventory),
    "partitions" -> ujson.Arr.from(partitionLedger),
    "flows" -> ujson.Arr.from(flows)
  )
  val encoded = ujson.write(result)
  require(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 16777216, "report_budget_exceeded")
  java.nio.file.Files.writeString(java.nio.file.Paths.get(outFile), encoded)
}
