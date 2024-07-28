using HuaweiRequestSigner;
using RestSharp;

namespace TestApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello, Huawei World!");

            var accessKey = "";
            var secretKey = "";
            var region = "";
            var projectId = "";
            // var accountId = "";
            var domain = "";

            var signer = new RequestSigner();
            try
            {
                var requestUrl = $"https://ecs.{region}.myhuaweicloud.{domain}/v1/{projectId}/cloudservers/detail";

                var headers = signer.GetRequestHeaders(requestUrl, accessKey, secretKey);

                var client = new RestClient();

                var request = new RestRequest(requestUrl, method: Method.Get);
                request.AddHeaders(headers.ToList());

                var response = client.Execute(request);
                Console.WriteLine("RESPONSE");
                Console.WriteLine(response.Content);
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: Msg: {)", ex.Message);
            }
        }
    }
}
