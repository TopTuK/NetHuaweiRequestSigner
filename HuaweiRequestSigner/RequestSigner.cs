using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Cache;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HuaweiRequestSigner
{
    /// <summary>
    /// 
    /// </summary>
    public class RequestSigner
    {
        public string RequestTime { get; set; }

        public RequestSigner(string? requestTime = null)
        {
            RequestTime = (requestTime != null)
                ? requestTime
                : DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ");
        }

        private string GetStandardRequest(string requestUrl, string requestMethod, string payload)
        {
            var requestParts = new List<string>();

            var uri = new Uri(requestUrl);

            // Step 1 - Method
            requestParts.Add(requestMethod);

            // Step 2 - Path
            var uriPath = uri.AbsolutePath;
            if (!uriPath.EndsWith('/')) uriPath += '/';
            requestParts.Add(uriPath);

            // Step 3 - Query string
            requestParts.Add(uri.Query);

            // Step 4 - Header
            // All letters in a header are converted to lowercase letters, and all spaces before and after the header are deleted.
            // All headers are sorted in alphabetically ascending order.
            Dictionary<string, string> headers = new()
            {
                { "host", uri.Host },
                { "x-sdk-date", RequestTime }
            };
            var headersList = headers
                .Select(kv => $"{kv.Key.ToLower()}:{kv.Value}")
                .ToList();
            headersList.Sort();
            var canonicalHeaders = string.Join("\n", headersList);
            requestParts.Add(canonicalHeaders);

            // Step 5 - Signed Headers
            requestParts.Add("");
            var signed_headers = "host;x-sdk-date";
            requestParts.Add(signed_headers);

            // Step 6 - Request Payload
            // HexEncode(Hash(RequestPayload)
            string requestPayload;

            using (var sha256 = SHA256.Create())
            {
                byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
                byte[] hashBytes = sha256.ComputeHash(payloadBytes);
                requestPayload = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }

            requestParts.Add(requestPayload);

            // Return
            var result = string.Join('\n', requestParts);
            return result;
        }

        private string GetSignedString(string standardRequest)
        {
            string algorithm = "SDK-HMAC-SHA256";
            string requestPayload;

            using (var sha256 = SHA256.Create())
            {
                byte[] payloadBytes = Encoding.UTF8.GetBytes(standardRequest);
                byte[] hashBytes = sha256.ComputeHash(payloadBytes);
                requestPayload = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }

            string stringToSign = $"{algorithm}\n{RequestTime}\n{requestPayload}";

            return stringToSign;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="requestUrl"></param>
        /// <param name="secretKey"></param>
        /// <param name="requestMethod"></param>
        /// <param name="payload"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public string GetSignature(string requestUrl, string secretKey, string requestMethod = "GET", string payload = "")
        {
            var standardRequest = GetStandardRequest(requestUrl, requestMethod, payload);
            var stringToSign = GetSignedString(standardRequest);

            string signature;
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
            {
                byte[] data = Encoding.UTF8.GetBytes(stringToSign);
                byte[] hashBytes = hmac.ComputeHash(data);
                signature = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }

            return signature;
        }

        /// <summary>
        /// Get request headers
        /// </summary>
        /// <param name="requestUrl"></param>
        /// <param name="accessKey"></param>
        /// <param name="secretKey"></param>
        /// <param name="requestMethod"></param>
        /// <param name="payload"></param>
        /// <returns></returns>
        public IReadOnlyDictionary<string, string> GetRequestHeaders(string requestUrl, string accessKey, string secretKey,
            string requestMethod = "GET", string payload = "")
        {
            var signature = GetSignature(requestUrl, secretKey, requestMethod, payload);
            var authorization = GetAuthorizationString(accessKey, signature);

            Dictionary<string, string> headers = new()
            {
                { "Content-Type", "application/json" },
                { "x-sdk-date", RequestTime },
                { "Authorization", authorization }
            };

            return headers;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="accessKey"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        static public string GetAuthorizationString(string accessKey, string signature)
            => $"SDK-HMAC-SHA256 Access={accessKey}, SignedHeaders=host;x-sdk-date, Signature={signature}";
    }
}
