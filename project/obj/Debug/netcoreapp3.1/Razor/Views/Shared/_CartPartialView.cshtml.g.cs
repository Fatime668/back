#pragma checksum "C:\Users\user\source\repos\project\project\Views\Shared\_CartPartialView.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "43d79c59d30f1778da3f439c80cf5f0f873da826"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Shared__CartPartialView), @"mvc.1.0.view", @"/Views/Shared/_CartPartialView.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "C:\Users\user\source\repos\project\project\Views\_ViewImports.cshtml"
using project.ViewModels;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "C:\Users\user\source\repos\project\project\Views\_ViewImports.cshtml"
using project.Models;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"43d79c59d30f1778da3f439c80cf5f0f873da826", @"/Views/Shared/_CartPartialView.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"5fcded930a32da9b72a26bc2560ba7528a8701cd", @"/Views/_ViewImports.cshtml")]
    public class Views_Shared__CartPartialView : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n");
#nullable restore
#line 2 "C:\Users\user\source\repos\project\project\Views\Shared\_CartPartialView.cshtml"
 foreach (var cart in Model)
{

#line default
#line hidden
#nullable disable
            WriteLiteral("    <div class=\"col-12 col-sm-6 col-md-6 col-lg-4\">\r\n        <div class=\"cart-item\">\r\n            <div class=\"icon\">\r\n                <i");
            BeginWriteAttribute("class", " class=\"", 171, "\"", 192, 1);
#nullable restore
#line 7 "C:\Users\user\source\repos\project\project\Views\Shared\_CartPartialView.cshtml"
WriteAttributeValue("", 179, cart.IconUrl, 179, 13, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral("></i>\r\n            </div>\r\n            <div class=\"cart-txt\">\r\n                <h2>");
#nullable restore
#line 10 "C:\Users\user\source\repos\project\project\Views\Shared\_CartPartialView.cshtml"
               Write(cart.Title);

#line default
#line hidden
#nullable disable
            WriteLiteral("</h2>\r\n                <p>");
#nullable restore
#line 11 "C:\Users\user\source\repos\project\project\Views\Shared\_CartPartialView.cshtml"
              Write(cart.Description);

#line default
#line hidden
#nullable disable
            WriteLiteral("</p>\r\n            </div>\r\n        </div>\r\n    </div>\r\n");
#nullable restore
#line 15 "C:\Users\user\source\repos\project\project\Views\Shared\_CartPartialView.cshtml"
}

#line default
#line hidden
#nullable disable
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591