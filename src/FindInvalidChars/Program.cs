using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Globalization;

namespace ActiveDirectoryDiag
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            string domainName = GetTargetDomainNameFromUser();

            string groupName = GetTargetGroupNameFromUser();

            using (DirectorySearcher searcher = GetRootDomainDirectorySearcher())
            {
                IDictionary<uint, string> groupPrimaryTokenToPathDict = FindTargetGroups(searcher, domainName, groupName);
                if (groupPrimaryTokenToPathDict.Count == 0)
                {
                    Console.WriteLine($"Couldn`t find group: {groupName} in domain: {domainName}, please validate your inputs.");
                    return;
                }

                foreach (var groupInfo in groupPrimaryTokenToPathDict)
                {
                    FindInvalidCharsInGroup(searcher, groupInfo);
                }
            }
        }

        private static void FindInvalidCharsInGroup(
            DirectorySearcher searcher, 
            KeyValuePair<uint, string> groupInfo)
        {
            var groupPath = groupInfo.Value;
            var primaryGroupToken = groupInfo.Key;

            Console.WriteLine($"Finding invalid characters in group: {groupPath}.");

            searcher.SearchScope = SearchScope.Subtree;
            searcher.Filter = string.Format(CultureInfo.InvariantCulture, "(PrimaryGroupID={0})", primaryGroupToken);
            searcher.PageSize = 200;

            searcher.PropertiesToLoad.Add("MailAddress");
            searcher.PropertiesToLoad.Add("mail");
            searcher.PropertiesToLoad.Add("displayName");
            searcher.PropertiesToLoad.Add("description");
            searcher.PropertiesToLoad.Add("groupType");
            searcher.PropertiesToLoad.Add("sAMAccountName");

            using (SearchResultCollection results = searcher.FindAll())
            {
                var counter = 0;
                foreach (SearchResult result in results)
                {
                    FindInvalidCharsInGroupMemberProperties(result);
                    if (++counter % 1000 == 0)
                    {
                        Console.WriteLine($"Scaned {counter} users.");
                    }
                }
            }
        }

        private static void FindInvalidCharsInGroupMemberProperties(SearchResult groupMember)
        {
            if (groupMember == null)
            {
                return;
            }

            var dName = groupMember.Properties["distinguishedname"][0];
            foreach (DictionaryEntry property in groupMember.Properties)
            {
                string value = ((property.Value) as ResultPropertyValueCollection)[0] as string;

                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                try
                {
                    CheckStringForInvalidCharacters(value, property.Key as string, true);
                }
                catch (Exception)
                {
                    Console.WriteLine("Found invalid characters for Member DN:{0}, property:{1}, value:{2}", dName, property.Key, value);
                }
            }
        }

        private static string GetTargetGroupNameFromUser()
        {
            Console.WriteLine("Please provide the target group name that you want to search for invalid characters:");

            var groupName = Console.ReadLine();
            while (string.IsNullOrEmpty(groupName))
            {
                Console.WriteLine("Please provide a valid group name.");
                groupName = Console.ReadLine();
            }

            return groupName;
        }

        private static string GetTargetDomainNameFromUser()
        {
            Console.WriteLine("Please provide the target domain name:");

            var domainName = Console.ReadLine();
            while (string.IsNullOrEmpty(domainName))
            {
                Console.WriteLine("Please provide a valid domain name.");
                domainName = Console.ReadLine();
            }

            return domainName;
        }

        private static DirectorySearcher GetRootDomainDirectorySearcher()
        {
            var forest = System.DirectoryServices.ActiveDirectory.Forest.GetCurrentForest();
            var globalCatalog = forest.FindGlobalCatalog();

            return globalCatalog.GetDirectorySearcher();
        }

        private static IDictionary<uint, string> FindTargetGroups(DirectorySearcher searcher, string domainName, string groupName)
        {
            IDictionary<uint, string> groupPrimaryTokenToPathDict = new Dictionary<uint, string>();

            if (searcher == null)
            {
                throw new Exception("Failed to get a AD searcher.");
            }

            searcher.Filter = string.Format("(anr={0})", groupName);
            searcher.PropertiesToLoad.Add("distinguishedname");
            searcher.PropertiesToLoad.Add("objectSid");

            searcher.SearchScope = SearchScope.Subtree;
            searcher.ClientTimeout = new TimeSpan(0, 1, 0);

            using (SearchResultCollection results = searcher.FindAll())
            {
                foreach (SearchResult result in results)
                {
                    var groupPath = result.Path;

                    if (!string.IsNullOrEmpty(groupPath) && groupPath.Contains(domainName))
                    {
                        Console.WriteLine($"Found matching group: {result.Path} in domain: {domainName}.");

                        var primaryToken = GetSidRid(result.Properties["objectSid"][0] as byte[]);
                        groupPrimaryTokenToPathDict.Add(primaryToken, result.Path);
                    }
                }
            }

            return groupPrimaryTokenToPathDict;
        }

        private static void CheckStringForInvalidCharacters(String stringVar, String stringVarName, Boolean allowCrLf)
        {
            for (int i = 0; i < stringVar.Length; i++)
            {
                if (IsIllegalInputCharacter(stringVar[i], allowCrLf))
                {
                    throw new ArgumentException();
                }
            }
        }

        private static bool IsIllegalInputCharacter(char c, Boolean allowCrLf = false)
        {
            if (allowCrLf == true && (c == '\r' || c == '\n'))
            {
                return false;
            }

            UnicodeCategory cat = Char.GetUnicodeCategory(c);

            // see http://www.w3.org/TR/REC-xml/#charsets
            return (cat == UnicodeCategory.LineSeparator
                || cat == UnicodeCategory.ParagraphSeparator
                || cat == UnicodeCategory.Control
                || cat == UnicodeCategory.Format
                || cat == UnicodeCategory.OtherNotAssigned);
        }

        private static uint GetSidRid(byte[] binarySid)
        {
            // convert the binary sid into it's parts....
            int revision;
            ulong authority;
            uint[] subAuthorities = DecodeSid(binarySid, out revision, out authority);

            // we can only determine the RID for windows SIDs
            if (authority != 5)
            {
                return 0;
            }

            // must have 5 sub authorities
            if (subAuthorities.Length != 5)
            {
                return 0;
            }

            // the RID is the last Sub-Authority
            return subAuthorities[4];
        }

        private static uint[] DecodeSid(byte[] binarySid, out int revision, out ulong authority)
        {
            revision = binarySid[0];

            int subAuthoritiesCount = binarySid[1];

            authority =
                (ulong)(
                (((long)binarySid[2]) << 40) +
                (((long)binarySid[3]) << 32) +
                (((long)binarySid[4]) << 24) +
                (((long)binarySid[5]) << 16) +
                (((long)binarySid[6]) << 8) +
                (((long)binarySid[7])));

            uint[] subAuthorities = new uint[subAuthoritiesCount];

            //
            // Subauthorities are represented in big-endian format
            //
            for (byte i = 0; i < subAuthoritiesCount; i++)
            {
                subAuthorities[i] =
                    (((uint)binarySid[8 + 4 * i + 0]) << 0) +
                    (((uint)binarySid[8 + 4 * i + 1]) << 8) +
                    (((uint)binarySid[8 + 4 * i + 2]) << 16) +
                    (((uint)binarySid[8 + 4 * i + 3]) << 24);
            }

            return subAuthorities;
        }
    }
}