using Newtonsoft.Json.Linq;
using System;
using System.Linq.Expressions;

namespace ClientDetectionAgent
{
    public class Criteria
    {
        public string Event { get; set; }
        public Expression<Func<JObject, bool>> Predicate { get; set; }
    }
}